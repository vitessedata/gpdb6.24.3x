#include "../exx_int.h"

#include "decode.h"
#include "exx/exx_trans.h"
#include "aggop.h"
#include "../util/decimal.h"
#include "../util/exx_sarg.h"

static inline Datum decode_int16(char *data) {
	int16_t *p = (int16_t *)data;
	return Int16GetDatum(*p);
}

static inline Datum decode_char(char *p) {
	return CharGetDatum(*p);
}

static inline Datum decode_int32(char *data) {
	int32_t *p = (int32_t *)data;
	return Int32GetDatum(*p);
}

static inline Datum decode_int64(char *data) {
	int64_t *p = (int64_t *)data;
	return Int64GetDatum(*p);
}

static inline Datum decode_int128(char *data) {
	__int128_t *p = (__int128_t *)data;
	return PointerGetDatum(p);
}

static inline Datum decode_float(char *data) {
	float *p = (float *)data;
	return Float4GetDatum(*p);
}

static inline Datum decode_double(char *data) {
	double *p = (double *)data;
	return Float8GetDatum(*p);
}

static inline Datum decode_date(char *data) {
	int32_t d = *((int32_t *)data);
	d -= (POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE);
	return Int32GetDatum(d);
}
static inline Datum decode_time(char *data) {
	int64_t t = *((int64_t *)data);
	return Int64GetDatum(t);
}

static Datum decode_timestamp(char *data) {
	int64_t ts = *((int64_t *)data);
	Timestamp epoch_ts = SetEpochTimestamp();
	ts += epoch_ts;
	return Int64GetDatum(ts);
}

static Datum decode_dateav(xrg_array_header_t *arr, int sz, Form_pg_attribute pg_attr) {
	int16_t ptyp = xrg_array_ptyp(arr);
	int16_t ltyp = xrg_array_ltyp(arr);
	int ndim = xrg_array_ndim(arr);
	int ndims = *xrg_array_dims(arr);
	char *p = xrg_array_data_ptr(arr);
	int itemsz = xrg_typ_size(ptyp);
	char *nullmap = xrg_array_nullbitmap(arr);

	Insist(sz = xrg_array_size(arr));
	Insist(ltyp == XRG_LTYP_DATE);
	Insist(itemsz == sizeof(int32_t));

	if (ndim == 0) {
		ArrayType *ret = (ArrayType *) arr;
		ret->elemtype = pg_array_to_element_oid(pg_attr->atttypid);
		SET_VARSIZE(ret, sz);
		return PointerGetDatum(ret);
	} 

	for (int i = 0 ; i < ndims ; i++) {
		if (!xrg_array_get_isnull(nullmap, i)) {
			*((int32_t *)p) -= (POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE);
			p += sizeof(int32_t);
		}
	}
	ArrayType *pga = (ArrayType *) arr;
	pga->elemtype = pg_array_to_element_oid(pg_attr->atttypid);
	SET_VARSIZE(pga, sz);
	return PointerGetDatum(pga);
}

static Datum decode_timestampav(xrg_array_header_t *arr, int sz, Form_pg_attribute pg_attr) {
	Timestamp epoch_ts = SetEpochTimestamp();
	int16_t ptyp = xrg_array_ptyp(arr);
	int16_t ltyp = xrg_array_ltyp(arr);
	int ndim = xrg_array_ndim(arr);
	int ndims = *xrg_array_dims(arr);
	char *p = xrg_array_data_ptr(arr);
	int itemsz = xrg_typ_size(ptyp);
	char *nullmap = xrg_array_nullbitmap(arr);

	Insist(sz = xrg_array_size(arr));
	Insist(ltyp == XRG_LTYP_TIMESTAMP);
	Insist(itemsz == sizeof(int64_t));

	if (ndim == 0) {
		ArrayType *ret = (ArrayType *) arr;
		ret->elemtype = pg_array_to_element_oid(pg_attr->atttypid);
		SET_VARSIZE(ret, sz);
		return PointerGetDatum(ret);
	} 

	for (int i = 0 ; i < ndims ; i++) {
		if (!xrg_array_get_isnull(nullmap, i)) {
			*((int64_t *)p) += epoch_ts;
			p += sizeof(int64_t);
		}
	}
	ArrayType *pga = (ArrayType *) arr;
	pga->elemtype = pg_array_to_element_oid(pg_attr->atttypid);
	SET_VARSIZE(pga, sz);
	return PointerGetDatum(pga);
}

static inline int32_t pgva_pack(char *dst, const void *ptr, int32_t len)
{
	SET_VARSIZE(dst, len + 4);
	memcpy(dst+4, ptr, len);
	return len+4;
}

static Datum decode_stringav(xrg_array_header_t *arr, int sz, Form_pg_attribute pg_attr) {
	int16_t ptyp = xrg_array_ptyp(arr);
	int16_t ltyp = xrg_array_ltyp(arr);
	int ndim = xrg_array_ndim(arr);
	int ndims = *xrg_array_dims(arr);
	char *p = xrg_array_data_ptr(arr);
	int itemsz = xrg_typ_size(ptyp);
	char *nullmap = xrg_array_nullbitmap(arr);

	Insist(sz = xrg_array_size(arr));
	Insist(ltyp == XRG_LTYP_STRING);
	Insist(itemsz == -1);

	if (ndim == 0) {
		ArrayType *ret = (ArrayType *) arr;
		ret->elemtype = pg_array_to_element_oid(pg_attr->atttypid);
		SET_VARSIZE(ret, sz);
		return PointerGetDatum(ret);
	} 

	int total = 0;
	for (int i = 0 ; i < ndims ; i++) {
		if (!xrg_array_get_isnull(nullmap, i)) {
			int len = xrg_bytea_len(p);
			total += xrg_align(4, len+4);
			p += len+4;
		}
	}

	ArrayType *pga = 0;
	if (xrg_array_hasnull(arr)) {
		total += ARR_OVERHEAD_WITHNULLS(ndim, ndims);
		pga = (ArrayType *) palloc(total);
		memcpy(pga, arr, ARR_OVERHEAD_WITHNULLS(ndim, ndims));
	} else {
		total += ARR_OVERHEAD_NONULLS(ndim);
		pga = (ArrayType *) palloc(total);
		memcpy(pga, arr, ARR_OVERHEAD_NONULLS(ndim));
	}

	pga->elemtype = pg_array_to_element_oid(pg_attr->atttypid);
	SET_VARSIZE(pga, total);

	char *pgp = ARR_DATA_PTR(pga);
	p = xrg_array_data_ptr(arr);
	
	for (int i = 0 ; i < ndims ; i++) {
		if (!xrg_array_get_isnull(nullmap, i)) {
			int len = xrg_bytea_len(p);
			const char *data = xrg_bytea_ptr(p);
			pgp += xrg_align(4, pgva_pack(pgp, data, len));
			p += len + 4;
		}
	}

	return PointerGetDatum(pga);
}

static Datum decode_dec64av(xrg_array_header_t *arr, int sz, int precision, int scale, Form_pg_attribute pg_attr) {

	ArrayType *ret = 0;
	FmgrInfo flinfo;

	int16_t ptyp = xrg_array_ptyp(arr);
	int16_t ltyp = xrg_array_ltyp(arr);
	int ndim = xrg_array_ndim(arr);
	int ndims = *xrg_array_dims(arr);
	char *p = xrg_array_data_ptr(arr);
	int itemsz = xrg_typ_size(ptyp);
	char dst[MAX_DEC128_STRLEN];
	char *nullmap = xrg_array_nullbitmap(arr);

	Insist(sz = xrg_array_size(arr));
	Insist(ltyp == XRG_LTYP_DECIMAL);
	Insist(ptyp == XRG_PTYP_INT64);
	Insist(itemsz == sizeof(int64_t));
	Insist(ndim == 1);

	StringInfoData str;
	initStringInfo(&str);
	appendStringInfoCharMacro(&str, '{');
	for (int i = 0 ; i < ndims ; i++) {
		if (i > 0) {
			appendStringInfoCharMacro(&str, ',');
		}
		if (!xrg_array_get_isnull(nullmap, i)) {
			int64_t v = *((int64_t *)p);
			decimal64_to_string(v, precision, scale, dst, sizeof(dst));
			appendStringInfoString(&str, dst);
			p += sizeof(int64_t);
		}
	}
	appendStringInfoCharMacro(&str, '}');

	memset(&flinfo, 0, sizeof(FmgrInfo));
	fmgr_info_cxt(fmgr_internal_function("array_in"), &flinfo, CurrentMemoryContext);
	ret = (ArrayType *) InputFunctionCall(&flinfo, str.data, pg_array_to_element_oid(pg_attr->atttypid), pg_attr->atttypmod);
	return PointerGetDatum(ret);
}

static Datum decode_dec128av(xrg_array_header_t *arr, int sz, int precision, int scale, Form_pg_attribute pg_attr) {

	ArrayType *ret = 0;
	FmgrInfo flinfo;

	int16_t ptyp = xrg_array_ptyp(arr);
	int16_t ltyp = xrg_array_ltyp(arr);
	int ndim = xrg_array_ndim(arr);
	int ndims = *xrg_array_dims(arr);
	char *p = xrg_array_data_ptr(arr);
	int itemsz = xrg_typ_size(ptyp);
	char dst[MAX_DEC128_STRLEN];
	char *nullmap = xrg_array_nullbitmap(arr);

	Insist(sz = xrg_array_size(arr));
	Insist(ltyp == XRG_LTYP_DECIMAL);
	Insist(ptyp == XRG_PTYP_INT128);
	Insist(itemsz == sizeof(__int128_t));
	Insist(ndim == 1);

	StringInfoData str;
	initStringInfo(&str);
	appendStringInfoCharMacro(&str, '{');
	for (int i = 0 ; i < ndims ; i++) {
		if (i > 0) {
			appendStringInfoCharMacro(&str, ',');
		}
		if (!xrg_array_get_isnull(nullmap, i)) {
			__int128_t v = 0;
			memcpy(&v, p, sizeof(__int128_t));
			decimal128_to_string(v, precision, scale, dst, sizeof(dst));
			appendStringInfoString(&str, dst);
			p += sizeof(__int128_t);
		}
	}

	appendStringInfoCharMacro(&str, '}');

	memset(&flinfo, 0, sizeof(FmgrInfo));
	fmgr_info_cxt(fmgr_internal_function("array_in"), &flinfo, CurrentMemoryContext);
	ret = (ArrayType *) InputFunctionCall(&flinfo, str.data, pg_array_to_element_oid(pg_attr->atttypid), pg_attr->atttypmod);
	return PointerGetDatum(ret);
}

static Datum decode_decimalav(xrg_array_header_t *arr, int sz, int precision, int scale, Form_pg_attribute pg_attr) {
	int16_t ptyp = xrg_array_ptyp(arr);
	int16_t ltyp = xrg_array_ltyp(arr);
	int ndim = xrg_array_ndim(arr);

	Insist(sz = xrg_array_size(arr));
	Insist(ltyp == XRG_LTYP_DECIMAL);

	if (ndim == 0) {
		ArrayType *ret = (ArrayType *) arr;
		ret->elemtype = pg_array_to_element_oid(pg_attr->atttypid);
		SET_VARSIZE(ret, sz);
		return PointerGetDatum(ret);
	} 

	switch (ptyp) {
	case XRG_PTYP_INT64:
		return decode_dec64av(arr, sz, precision, scale, pg_attr);
		break;
	case XRG_PTYP_INT128:
		return decode_dec128av(arr, sz, precision, scale, pg_attr);
		break;
	default:
		break;
	}
	return 0;
}

static Datum decode_defaultav(xrg_array_header_t *arr, int sz, Form_pg_attribute pg_attr) {
	Insist(sz = xrg_array_size(arr));
	ArrayType *pga = (ArrayType *) arr;
	pga->elemtype = pg_array_to_element_oid(pg_attr->atttypid);
	SET_VARSIZE(pga, sz);
	return PointerGetDatum(pga);
}

/* decode functions */

/**
 * decode basic data type such as fixed point data type and string from XRG format to PG format
 */
int decode_var(struct kite_target_t *tgt, xrg_iter_t *iter, Datum *pg_datum, bool *pg_isnull) {
	Insist(tgt->attrs && (list_length(tgt->attrs) == 1));

	int idx = linitial_int(tgt->attrs);
	Insist(idx < iter->nvec);

	char *data = iter->value[idx];
	char flag = *iter->flag[idx];
	int ltyp = iter->attr[idx].ltyp;
	int ptyp = iter->attr[idx].ptyp;
	int precision = iter->attr[idx].precision;
	int scale = iter->attr[idx].scale;

	// data in iter->value[idx] and iter->flag[idx] and iter->attrs[idx].ptyp
	*pg_isnull = (flag & XRG_FLAG_NULL);

	switch (ltyp) {
	case XRG_LTYP_NONE:
		// primitive type. no decode here
		switch (ptyp) {
		case XRG_PTYP_INT8: {
			*pg_datum = decode_char(data);
		} break;
		case XRG_PTYP_INT16: {
			*pg_datum = decode_int16(data);
		} break;
		case XRG_PTYP_INT32: {
			*pg_datum = decode_int32(data);
		} break;
		case XRG_PTYP_INT64: {
			*pg_datum = decode_int64(data);
		} break;
		case XRG_PTYP_INT128: {
			*pg_datum = decode_int128(data);
		} break;
		case XRG_PTYP_FP32: {
			*pg_datum = decode_float(data);
		} break;
		case XRG_PTYP_FP64: {
			*pg_datum = decode_double(data);
		} break;
		default: {
			elog(ERROR, "decode_var: invalid physcial type %d with NONE logical type", ptyp);
			return -1;
		}
		}
		return 0;
	case XRG_LTYP_DATE: {
		*pg_datum = (flag & XRG_FLAG_NULL) ? 0 : decode_date(data);
	}
		return 0;
	case XRG_LTYP_TIME: {
		*pg_datum = (flag & XRG_FLAG_NULL) ? 0 : decode_time(data);
	}
		return 0;
	case XRG_LTYP_TIMESTAMP: {
		*pg_datum = (flag & XRG_FLAG_NULL) ? 0 : decode_timestamp(data);
	}
		return 0;
	case XRG_LTYP_INTERVAL: {
		*pg_datum = (flag & XRG_FLAG_NULL) ? 0 : PointerGetDatum((__int128_t *)data);
	}
		return 0;
	case XRG_LTYP_DECIMAL:
	case XRG_LTYP_STRING:
	case XRG_LTYP_ARRAY:
		break;
	default: {
		elog(ERROR, "invalid xrg logical type %d", ltyp);
		return -1;
	}
	}

	if (ltyp == XRG_LTYP_DECIMAL && ptyp == XRG_PTYP_INT64) {
		int64_t v = *((int64_t *)data);
		char dst[MAX_DEC128_STRLEN];
		decimal64_to_string(v, precision, scale, dst, sizeof(dst));
		FmgrInfo flinfo;
		memset(&flinfo, 0, sizeof(FmgrInfo));
		flinfo.fn_addr = numeric_in;
		flinfo.fn_nargs = 3;
		flinfo.fn_strict = true;
		*pg_datum = InputFunctionCall(&flinfo, dst, 0, tgt->pg_attr->atttypmod);
		return 0;
	}

	if (ltyp == XRG_LTYP_DECIMAL && ptyp == XRG_PTYP_INT128) {
		__int128_t v = *((__int128_t *)data);
		char dst[MAX_DEC128_STRLEN];
		decimal128_to_string(v, precision, scale, dst, sizeof(dst));
		FmgrInfo flinfo;
		memset(&flinfo, 0, sizeof(FmgrInfo));
		flinfo.fn_addr = numeric_in;
		flinfo.fn_nargs = 3;
		flinfo.fn_strict = true;
		*pg_datum = InputFunctionCall(&flinfo, dst, 0, tgt->pg_attr->atttypmod);
		return 0;
	}

	if (ltyp == XRG_LTYP_STRING && ptyp == XRG_PTYP_BYTEA) {
		int sz = xrg_bytea_len(data);
		if (flag & XRG_FLAG_NULL) {
			*pg_datum = 0;
		} else {
			SET_VARSIZE(data, sz + VARHDRSZ);
			*pg_datum = PointerGetDatum(data);
		}
		return 0;
	}

	// TODO: date, timestamp, numeric need further processing
	if (ltyp == XRG_LTYP_ARRAY && ptyp == XRG_PTYP_BYTEA) {
		xrg_array_header_t *ptr = (xrg_array_header_t *) xrg_bytea_ptr(data);
		int sz = xrg_bytea_len(data);
		//int16_t array_ptyp = xrg_array_ptyp(ptr);
		int16_t array_ltyp = xrg_array_ltyp(ptr);
		if (flag & XRG_FLAG_NULL) {
			*pg_datum = 0;
		} else {

			switch (array_ltyp) {
			case XRG_LTYP_DATE:
			{
				*pg_datum = decode_dateav(ptr, sz, tgt->pg_attr);
					break;
			}
			case XRG_LTYP_TIMESTAMP:
			{
				*pg_datum = decode_timestampav(ptr, sz, tgt->pg_attr);
				break;
			}
			case XRG_LTYP_STRING:
			{
				*pg_datum = decode_stringav(ptr, sz, tgt->pg_attr);
				break;
			}
			case XRG_LTYP_DECIMAL:
			{
				*pg_datum = decode_decimalav(ptr, sz, precision, scale, tgt->pg_attr);
				break;
			}
			default:
				*pg_datum = decode_defaultav(ptr, sz, tgt->pg_attr);
				break;
			}
		}
		return 0;
	}

	return 0;
}

/**
 * decode AVG int64 column.
 * XRG will split AVG column into SUM and COUNT and finally convert to 
 * struct Int128AggState (See utils/adt/numeric.)
 */
int decode_avg_int64(struct kite_target_t *tgt, xrg_iter_t *iter, Datum *pg_datum, bool *pg_isnull) {
	Insist(tgt->attrs && (list_length(tgt->attrs) == 2));

	int idx0 = linitial_int(tgt->attrs);
	int idx1 = lsecond_int(tgt->attrs);
	Insist(idx0 < iter->nvec && idx1 < iter->nvec);

	char *data0 = iter->value[idx0];
	//char flag0 = *iter->flag[idx0];
	int ltyp0 = iter->attr[idx0].ltyp;
	int ptyp0 = iter->attr[idx0].ptyp;

	Insist(ltyp0 == XRG_LTYP_NONE && ptyp0 == XRG_PTYP_INT64);

	char *data1 = iter->value[idx1];
	//char flag1 = *iter->flag[idx1];
	int ltyp1 = iter->attr[idx1].ltyp;
	int ptyp1 = iter->attr[idx1].ptyp;

	Insist(ltyp1 == XRG_LTYP_NONE && ptyp1 == XRG_PTYP_INT64);

	if (!tgt->data) {
		tgt->data = palloc(sizeof(ExxInt128AggState));
	}
	ExxInt128AggState *p = (ExxInt128AggState *)tgt->data;

	int128 sum = *((int64_t *)data0);
	int64 count = *((int64_t *)data1);
	;

	p->calcSumX2 = false;
	p->N = count;
	p->sumX = sum;
	p->sumX2 = 0;

	*pg_isnull = false;
	*pg_datum = PointerGetDatum(p);

	return 0;
}

/**
 * decode AVG int128 column.
 * XRG will split AVG column into SUM and COUNT and finally convert to 
 * struct Int128AggState/ExxInt128AggState (See utils/adt/numeric.)
 */
int decode_avg_int128(struct kite_target_t *tgt, xrg_iter_t *iter, Datum *pg_datum, bool *pg_isnull) {
	Insist(tgt->attrs && (list_length(tgt->attrs) == 2));

	int idx0 = linitial_int(tgt->attrs);
	int idx1 = lsecond_int(tgt->attrs);
	Insist(idx0 < iter->nvec && idx1 < iter->nvec);

	char *data0 = iter->value[idx0];
	//char flag0 = *iter->flag[idx0];
	int ltyp0 = iter->attr[idx0].ltyp;
	int ptyp0 = iter->attr[idx0].ptyp;
	Insist(ltyp0 == XRG_LTYP_NONE && ptyp0 == XRG_PTYP_INT128);

	char *data1 = iter->value[idx1];
	//char flag1 = *iter->flag[idx1];
	int ltyp1 = iter->attr[idx1].ltyp;
	int ptyp1 = iter->attr[idx1].ptyp;
	Insist(ltyp1 == XRG_LTYP_NONE && ptyp1 == XRG_PTYP_INT64);

	if (!tgt->data) {
		tgt->data = palloc(sizeof(ExxInt128AggState));
	}
	ExxInt128AggState *p = (ExxInt128AggState *)tgt->data;

	int128 sum = *((__int128_t *)data0);
	int64 count = *((int64_t *)data1);
	;

	p->calcSumX2 = false;
	p->N = count;
	p->sumX = sum;
	p->sumX2 = 0;

	*pg_isnull = false;
	*pg_datum = PointerGetDatum(p);
	return 0;
}

/**
 * decode AVG double column.
 * XRG will split AVG column into SUM and COUNT and finally convert to PG internal transdata
 * struct ExxFloatAvgTransdata (See include/exx/exx_trans.h)
 */
int decode_avg_double(struct kite_target_t *tgt, xrg_iter_t *iter, Datum *pg_datum, bool *pg_isnull) {
	Insist(tgt->attrs && (list_length(tgt->attrs) == 2));

	int idx0 = linitial_int(tgt->attrs);
	int idx1 = lsecond_int(tgt->attrs);
	Insist(idx0 < iter->nvec && idx1 < iter->nvec);

	char *data0 = iter->value[idx0];
	//char flag0 = *iter->flag[idx0];
	int ltyp0 = iter->attr[idx0].ltyp;
	int ptyp0 = iter->attr[idx0].ptyp;
	Insist(ltyp0 == XRG_LTYP_NONE && ptyp0 == XRG_PTYP_FP64);

	char *data1 = iter->value[idx1];
	//char flag1 = *iter->flag[idx1];
	int ltyp1 = iter->attr[idx1].ltyp;
	int ptyp1 = iter->attr[idx1].ptyp;
	Insist(ltyp1 == XRG_LTYP_NONE && ptyp1 == XRG_PTYP_INT64);

	if (!tgt->data) {
		tgt->data = palloc(sizeof(ExxFloatAvgTransdata));
	}
	ExxFloatAvgTransdata *p = (ExxFloatAvgTransdata *)tgt->data;

	double sum = *((double *)data0);
	int64 count = *((int64_t *)data1);
	;

	SET_VARSIZE(p, sizeof(ExxFloatAvgTransdata));
	p->arraytype.ndim = 1;
	p->arraytype.dataoffset = 0;
	p->arraytype.elemtype = FLOAT8OID;
	p->nelem = 3;
	p->lbound = 1;
	p->data[0] = count;
	p->data[1] = sum;
	p->data[2] = 0;

	*pg_isnull = false;
	*pg_datum = PointerGetDatum(p);
	return 0;
}

/**
 * decode AVG numeric column.
 * XRG will split AVG column into SUM and COUNT and finally convert to PG internal transdata
 * struct NumericAggState/ExxNumericAggState (See utils/adt/numeric.c)
 */
int decode_avg_numeric(struct kite_target_t *tgt, xrg_iter_t *iter, Datum *pg_datum, bool *pg_isnull) {
	Insist(tgt->attrs && (list_length(tgt->attrs) == 2));

	int idx0 = linitial_int(tgt->attrs);
	int idx1 = lsecond_int(tgt->attrs);
	Insist(idx0 < iter->nvec && idx1 < iter->nvec);

	char *data0 = iter->value[idx0];
	//char flag0 = *iter->flag[idx0];
	int ltyp0 = iter->attr[idx0].ltyp;
	int ptyp0 = iter->attr[idx0].ptyp;
	int precision0 = iter->attr[idx0].precision;
	int scale0 = iter->attr[idx0].scale;
	Insist(ltyp0 == XRG_LTYP_DECIMAL && ptyp0 == XRG_PTYP_INT128);

	char *data1 = iter->value[idx1];
	//char flag1 = *iter->flag[idx1];
	int ltyp1 = iter->attr[idx1].ltyp;
	int ptyp1 = iter->attr[idx1].ptyp;
	Insist(ltyp1 == XRG_LTYP_NONE && ptyp1 == XRG_PTYP_INT64);

	if (!tgt->data) {
		tgt->data = palloc(sizeof(ExxNumericAggState));
	}
	ExxNumericAggState *p = (ExxNumericAggState *)tgt->data;

	int128 i128 = *((__int128_t *)data0);
	int64 count = *((int64_t *)data1);
	;

	Datum sum;
	char dst[MAX_DEC128_STRLEN];

	decimal128_to_string(i128, precision0, scale0, dst, sizeof(dst));
	FmgrInfo flinfo;
	memset(&flinfo, 0, sizeof(FmgrInfo));
	flinfo.fn_addr = numeric_in;
	flinfo.fn_nargs = 3;
	flinfo.fn_strict = true;
	//elog(LOG, "avg_numeric: typmod = %d (can be -1)", tgt->pg_attr->atttypmod);

	sum = InputFunctionCall(&flinfo, dst, 0, tgt->pg_attr->atttypmod);

	p->sumX = DatumGetNumeric(sum);
	p->N = count;

	*pg_isnull = false;
	*pg_datum = PointerGetDatum(p);
	return 0;
}
