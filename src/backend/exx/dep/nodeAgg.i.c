// Copyright (c) 2018-2021, Vitesse Data Inc. All rights reserved.
#include "postgres.h"
#include "access/relscan.h"
#include "catalog/pg_type.h"
#include "catalog/pg_collation.h"
#include "executor/execdesc.h"
#include "executor/nodeAgg.h"
#include "utils/builtins.h" 
#include "utils/memutils.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "miscadmin.h"
#include "exx/exx.h"
#include "exx/exx_trans.h"
#include "nodeAgg.i.h"

/**
 * Aggregate data from kite external table (Kite formatted) to transdata (PG formatted)
 */
void
exx_bclv_advance_aggregates(AggState *aggstate, AggStatePerGroup pergroup,
				   MemoryManagerContainer *mem_manager)
{
	for (int aggno = 0; aggno < aggstate->numaggs; aggno++) {
		Datum value;
		bool isnull;
		bool ismax = false;

		AggStatePerAgg peraggstate = &aggstate->peragg[aggno];
		AggStatePerGroup pergroupstate = &pergroup[aggno];
		Aggref	   *aggref = peraggstate->aggref;

		ProjectionInfo *proj = peraggstate->evalproj; 
		ExprContext *ectxt = proj->pi_exprContext;
		TupleTableSlot *slot = ectxt->ecxt_outertuple;
		TupleDesc tdesc = slot->tts_tupleDescriptor;

		/* 
		 * int attrn = tdesc->natts - aggstate->numaggs + aggno + 1; 
		 *
		 * XXX: You would think we need to compute attrn above.  BUT, postgres aggstate->peragg, 
		 * the functions are coming in REVERSE order of the SQL!
		 *
		 * execQual.c, ExecInitExpr, T_Aggref, 
		 * aggstate->aggs = lcons(astate, aggstate->aggs)
		 *
		 * Yeah, right, lisp.
		 */
		int attrn = tdesc->natts - aggno;
		value = slot_getattr(slot, attrn, &isnull);

		switch (aggref->aggfnoid) {
			case 2147: // count
			case 2803: // count
				{
					if (!isnull) {
						pergroupstate->noTransValue = false;
						pergroupstate->transValueIsNull = false;
						pergroupstate->transValue += value;
					}
				}
				break;

			case 2100: // avg bigint
				{
					/* See utils/adt/numeric.c:numeric_poly_combine int8:2100, int4:2101, int2:2102 */

					// value should be ExxInt128AggState and not null
					if (isnull || value == 0) {
						break;
					}

					MemoryContext oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);
                                        aggstate->curperagg = peraggstate;

                                        FunctionCallInfo fcinfo = &peraggstate->transfn_fcinfo;
                                        FmgrInfo flinfo;
                                        memset(&flinfo, 0, sizeof(FmgrInfo));

                                        flinfo.fn_addr = numeric_poly_combine;
                                        flinfo.fn_nargs = 2;
                                        flinfo.fn_strict = true;

                                        InitFunctionCallInfoData(*fcinfo, &flinfo, 2, peraggstate->aggCollation,
                                                        (void *) aggstate, NULL);

                                        fcinfo->arg[0] = pergroupstate->transValue;
                                        fcinfo->argnull[0] = pergroupstate->transValueIsNull;;
                                        fcinfo->arg[1] = (Datum) value;
                                        fcinfo->argnull[1] = false;

                                        pergroupstate->transValue = FunctionCallInvoke(fcinfo);
                                        pergroupstate->noTransValue = false;
                                        pergroupstate->transValueIsNull = false;


                                        aggstate->curperagg = NULL;
                                        MemoryContextSwitchTo(oldContext);


				}
				break;
			case 2101: // avg integer
			case 2102: // avg smallint
				{

					if (isnull || value == 0) {
						break;
					}

                    MemoryContext oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);
                                        aggstate->curperagg = peraggstate;

                                        FunctionCallInfo fcinfo = &peraggstate->transfn_fcinfo;
                                        FmgrInfo flinfo;
                                        memset(&flinfo, 0, sizeof(FmgrInfo));

                                        flinfo.fn_addr = int4_avg_combine;
                                        flinfo.fn_nargs = 2;
                                        flinfo.fn_strict = true;

                                        InitFunctionCallInfoData(*fcinfo, &flinfo, 2, peraggstate->aggCollation,
                                                        (void *) aggstate, NULL);

                                        fcinfo->arg[0] = pergroupstate->transValue;
                                        fcinfo->argnull[0] = pergroupstate->transValueIsNull;;
                                        fcinfo->arg[1] = (Datum) value;
                                        fcinfo->argnull[1] = false;

                                        pergroupstate->transValue = FunctionCallInvoke(fcinfo);
                                        pergroupstate->noTransValue = false;
                                        pergroupstate->transValueIsNull = false;


                                        aggstate->curperagg = NULL;
                                        MemoryContextSwitchTo(oldContext);
				}
				break;
			case 2103: // avg numeric 
				{
					/* See utils/adt/numeric.c:numeric_avg_accum  numeric avg */
					if (isnull || value == 0) {
						break;
					}


					ExxNumericAggState *state = (ExxNumericAggState *) value;

					MemoryContext oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);
					aggstate->curperagg = peraggstate;

					FunctionCallInfo fcinfo = &peraggstate->transfn_fcinfo;
					FmgrInfo flinfo;
					memset(&flinfo, 0, sizeof(FmgrInfo));

					extern Datum exx_numeric_avg_combine(PG_FUNCTION_ARGS);
					flinfo.fn_addr = exx_numeric_avg_combine;
					flinfo.fn_nargs = 3;
					flinfo.fn_strict = true;

					InitFunctionCallInfoData(*fcinfo, &flinfo, 3, peraggstate->aggCollation,
							(void *) aggstate, NULL);

					fcinfo->arg[0] = pergroupstate->transValue;
					fcinfo->argnull[0] = pergroupstate->transValueIsNull;
					fcinfo->arg[1] = NumericGetDatum(state->sumX);
					fcinfo->argnull[1] = false;
					fcinfo->arg[2] = Int64GetDatum(state->N);
					fcinfo->argnull[2] = false;

					pergroupstate->transValue = FunctionCallInvoke(fcinfo);
					pergroupstate->noTransValue = false;
					pergroupstate->transValueIsNull = false;

					aggstate->curperagg = NULL;
					MemoryContextSwitchTo(oldContext);

				}
				break;
			case 2104: // avg float4
			case 2105: // avg float8
				{
					/* See utils/adt/float.c:float8_combine */
					// value should be ExxFloatAvgTransdata

					if (isnull || value == 0) {
						break;
					}

					MemoryContext oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);
					aggstate->curperagg = peraggstate;

					FunctionCallInfo fcinfo = &peraggstate->transfn_fcinfo;
					FmgrInfo flinfo;
					memset(&flinfo, 0, sizeof(FmgrInfo));

					flinfo.fn_addr = float8_combine;
					flinfo.fn_nargs = 2;
					flinfo.fn_strict = true;

					InitFunctionCallInfoData(*fcinfo, &flinfo, 2, peraggstate->aggCollation,
					(void *) aggstate, NULL);

					fcinfo->arg[0] = pergroupstate->transValue;
					fcinfo->argnull[0] = pergroupstate->transValueIsNull;;
					fcinfo->arg[1] = value;
					fcinfo->argnull[1] = false;

					pergroupstate->transValue = FunctionCallInvoke(fcinfo);
					pergroupstate->noTransValue = false;
					pergroupstate->transValueIsNull = false;

					aggstate->curperagg = NULL;
					MemoryContextSwitchTo(oldContext);

					break;
				}

			case 2107: // sum bigint
				{
					/* reference to executor/nodeAgg.c:invoke_agg_trans_func */
					// value should be (__int128_t *)

					if (isnull) {
						break;
					}

					MemoryContext oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);
					aggstate->curperagg = peraggstate;

					extern Datum exx_int128_avg_accum(PG_FUNCTION_ARGS);

					FunctionCallInfo fcinfo = &peraggstate->transfn_fcinfo;
					FmgrInfo flinfo;
					memset(&flinfo, 0, sizeof(FmgrInfo));

					flinfo.fn_addr = exx_int128_avg_accum;
					flinfo.fn_nargs = 2;
					flinfo.fn_strict = true;

					InitFunctionCallInfoData(*fcinfo, &flinfo, 2, peraggstate->aggCollation,
							(void *) aggstate, NULL);

					fcinfo->arg[0] = pergroupstate->transValue;
					fcinfo->argnull[0] = pergroupstate->transValueIsNull;;
					fcinfo->arg[1] = value;
					fcinfo->argnull[1] = false;

					pergroupstate->transValue = FunctionCallInvoke(fcinfo);
					pergroupstate->noTransValue = false;
					pergroupstate->transValueIsNull = false;


					aggstate->curperagg = NULL;
					MemoryContextSwitchTo(oldContext);

				}
				break;

			case 2108: // sum integer
			case 2109: // sum smallint
				{
					if (isnull) {
						break;
					}

					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						pergroupstate->transValue = value;
						pergroupstate->transValueIsNull = false;
						pergroupstate->noTransValue = false;
					} else {
						pergroupstate->transValue += value;
					}
				}
				break;

			case 2110: // sum float4
				{
					if (isnull) {
						break;
					}
					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						pergroupstate->transValue = value;
						pergroupstate->transValueIsNull = false;
						pergroupstate->noTransValue = false;
					} else {
						float a = DatumGetFloat4(pergroupstate->transValue);
						float b = DatumGetFloat4(value); 
						pergroupstate->transValue = Float4GetDatum(a+b); 
					}
				} 
				break;
	
			case 2111: // sum float8
				{
					if (isnull) {
						break;
					}
					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						pergroupstate->transValue = value;
						pergroupstate->transValueIsNull = false;
						pergroupstate->noTransValue = false;
					} else {
						double a = DatumGetFloat8(pergroupstate->transValue);
						double b = DatumGetFloat8(value); 
						pergroupstate->transValue = Float8GetDatum(a+b); 
					}
				} 
				break;

			case 2114: // sum numeric
				{
					/* See utils/adt/numeric.c numeric_avg_accum(PG_FUNCTION_ARGS) - avg sum() */
					/* reference to executor/nodeAgg.c:invoke_agg_trans_func */
					// value should be numeric
					if (isnull) {
						break;
					}
					MemoryContext oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);
					aggstate->curperagg = peraggstate;

					FunctionCallInfo fcinfo = &peraggstate->transfn_fcinfo;
					FmgrInfo flinfo;
					memset(&flinfo, 0, sizeof(FmgrInfo));

					flinfo.fn_addr = numeric_avg_accum;
					flinfo.fn_nargs = 2;
					flinfo.fn_strict = true;

					InitFunctionCallInfoData(*fcinfo, &flinfo, 2, peraggstate->aggCollation,
							(void *) aggstate, NULL);

					fcinfo->arg[0] = pergroupstate->transValue;
					fcinfo->argnull[0] = pergroupstate->transValueIsNull;;
					fcinfo->arg[1] = value;
					fcinfo->argnull[1] = false;

					pergroupstate->transValue = FunctionCallInvoke(fcinfo);
					pergroupstate->noTransValue = false;
					pergroupstate->transValueIsNull = false;

					aggstate->curperagg = NULL;
					MemoryContextSwitchTo(oldContext);

				}
				break;
			case 2115:  // max bigint
			case 2123:  // max time
			case 2125:  // max money
			case 2126:  // max timestamp
			case 2127:  // max timestamptz
				ismax = true;
				/* fall through with ismax set to true. */
				[[fallthrough]];
			case 2131:  // min bigint
			case 2139:  // min time
			case 2141:  // min money
			case 2142:  // min timestamp
			case 2143:  // min timestamptz
				{
					if (isnull) {
						break;
					}
					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						pergroupstate->transValue = value;
						pergroupstate->transValueIsNull = isnull; 
						pergroupstate->noTransValue = false;
					} else if (!isnull) {
						int64_t a = DatumGetInt64(pergroupstate->transValue);
						int64_t b = DatumGetInt64(value);
						if ((ismax && a < b) || (!ismax && a > b)) {
							pergroupstate->transValue = value;
						}
					}
				}
				break;

			case 2116:  // max integer
			case 2122:  // max date
				ismax = true;
				[[fallthrough]];
			case 2132:  // min integer
			case 2138:  // min date
				{
					if (isnull) {
						break;
					}
					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						pergroupstate->transValue = value;
						pergroupstate->transValueIsNull = isnull; 
						pergroupstate->noTransValue = false;
					} else if (!isnull) {
						int32_t a = DatumGetInt32(pergroupstate->transValue);
						int32_t b = DatumGetInt32(value);
						if ((ismax && a < b) || (!ismax && a > b)) {
							pergroupstate->transValue = value;
						}
					}
				}
				break;

			case 2117: // max smallint
				ismax = true;
				[[fallthrough]];
			case 2133: // min smallint
				{
					if (isnull) {
						break;
					}
					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						pergroupstate->transValue = value;
						pergroupstate->transValueIsNull = isnull; 
						pergroupstate->noTransValue = false;
					} else if (!isnull) {
						int16_t a = DatumGetInt16(pergroupstate->transValue);
						int16_t b = DatumGetInt16(value);
						if ((ismax && a < b) || (!ismax && a > b)) {
							pergroupstate->transValue = value;
						}
					}
				}
				break;

			case 2119: // max float4
				ismax = true;
				[[fallthrough]];
			case 2135: // min float4
				{
					if (isnull) {
						break;
					}
					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						pergroupstate->transValue = value;
						pergroupstate->transValueIsNull = isnull; 
						pergroupstate->noTransValue = false;
					} else if (!isnull) {
						float a = DatumGetFloat4(pergroupstate->transValue);
						float b = DatumGetFloat4(value);
						if ((ismax && a < b) || (!ismax && a > b)) {
							pergroupstate->transValue = value;
						}
					}
				}
				break;

			case 2120: // max float8
				ismax = true;
				[[fallthrough]];
			case 2136: // min float8
				{
					if (isnull) {
						break;
					}
					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						pergroupstate->transValue = value;
						pergroupstate->transValueIsNull = isnull; 
						pergroupstate->noTransValue = false;
					} else if (!isnull) {
						double a = DatumGetFloat8(pergroupstate->transValue);
						double b = DatumGetFloat8(value);
						if ((ismax && a < b) || (!ismax && a > b)) {
							pergroupstate->transValue = value;
						}
					}
				}
				break;
				
			case 2130: // max numeric
				ismax = true;
				[[fallthrough]];
			case 2146: // min numeric
				{
					if (isnull) {
						break;
					}
					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						pergroupstate->transValue = value;
						pergroupstate->transValueIsNull = isnull; 
						pergroupstate->noTransValue = false;
					} else if (!isnull) {
						Numeric a = DatumGetNumeric(pergroupstate->transValue);
						Numeric b = DatumGetNumeric(value);
						int ret = cmp_numerics(a, b);
						//if ((ismax && a < b) || (!ismax && a > b)) {
						if ((ismax && ret < 0) || (!ismax && ret > 0)) {
							pergroupstate->transValue = value;
						}
					}

				}
				break;
			case 2129: // max text
			case 2244: // max bpchar
				ismax = true;
				[[fallthrough]];
			case 2145: // min text
			case 2245: // min bpchar
				{
					if (isnull) {
						break;
					}
					MemoryContext oldContext = MemoryContextSwitchTo(aggstate->tmpcontext->ecxt_per_tuple_memory);
					if (pergroupstate->noTransValue || pergroupstate->transValueIsNull) {
						char *v = (char *)DatumGetPointer(value);
						char *vv = palloc(VARSIZE_ANY(v));
						memcpy(vv, v, VARSIZE_ANY(v));
						pergroupstate->transValue = PointerGetDatum(vv);
						pergroupstate->transValueIsNull = isnull; 
						pergroupstate->noTransValue = false;
					} else if (!isnull) {
						char *a = (char *)DatumGetPointer(pergroupstate->transValue);
						char *b = (char *)DatumGetPointer(value);
						int lena = VARSIZE_ANY_EXHDR(a);
						int lenb = VARSIZE_ANY_EXHDR(b);
						int ret = varstr_cmp(VARDATA_ANY(a), lena, VARDATA_ANY(b), lenb, C_COLLATION_OID);
						//if ((ismax && a < b) || (!ismax && a > b)) {
						if ((ismax && ret < 0) || (!ismax && ret > 0)) {
							// reuse the transValue if the memory buffer is big enough to hold the new value
							if (VARSIZE_ANY(a) < VARSIZE_ANY(b)) {
								char *vv = palloc(VARSIZE_ANY(b));
								memcpy(vv, b, VARSIZE_ANY(b));
								//pfree(a);  // free is expensive
								pergroupstate->transValue = PointerGetDatum(vv);
							} else {
								memcpy(a, b, VARSIZE_ANY(b));
							}

						}
					}
					MemoryContextSwitchTo(oldContext);
				}
				break;
			default:
				elog(ERROR, "Bad agg operation.");
		} 
	}
}
