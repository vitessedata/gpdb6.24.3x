// Copyright (c) 2018-2021, Vitesse Data Inc. All rights reserved.
#include "../exx_int.h"
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "exx_sarg.h"
#include "xrg.h"

#include "utils/builtins.h"
#include "utils/datetime.h"
#include "utils/inet.h"
#include "parser/parsetree.h"
#include "optimizer/var.h"
#include "optimizer/clauses.h"
#include "utils/array.h"
#include "utils/timestamp.h"

size_t xrg_typ_size(int16_t ptyp) {
	switch (ptyp) {
	case XRG_PTYP_INT8:
		return 1;
	case XRG_PTYP_INT16:
		return 2;
	case XRG_PTYP_INT32:
		return 4;
	case XRG_PTYP_INT64:
		return 8;
	case XRG_PTYP_INT128:
		return 16;
	case XRG_PTYP_FP32:
		return 4;
	case XRG_PTYP_FP64:
		return 8;
	case XRG_PTYP_BYTEA:
		return -1;
	default:
		break;
	}

	return 0;
}

const char *xrg_typ_str(int16_t ptyp, int16_t ltyp, bool is_array) {
	switch (ptyp) {
	case XRG_PTYP_INT8:
		return is_array ? "int8[]" : "int8";
	case XRG_PTYP_INT16:
		return is_array ? "int16[]" : "int16";
	case XRG_PTYP_INT32:
		switch (ltyp) {
		case XRG_LTYP_DATE:
			return is_array ? "date[]" : "date";
		default:
			return is_array ? "int32[]" : "int32";
		}
		break;
	case XRG_PTYP_INT64:
		switch (ltyp) {
		case XRG_LTYP_DECIMAL:
			return is_array ? "decimal[]" : "decimal";
		case XRG_LTYP_TIME:
			return is_array ? "time[]" : "time";
		case XRG_LTYP_TIMESTAMP:
			return is_array ? "timestamp[]" : "timestamp";
		default:
			return is_array ? "int64[]" : "int64";
		}

		break;
	case XRG_PTYP_INT128:
		switch (ltyp) {
		case XRG_LTYP_INTERVAL:
			return is_array ? "interval[]" : "interval";
		case XRG_LTYP_DECIMAL:
			return is_array ? "decimal[]" : "decimal";
		default:
			return is_array ? "int128[]" : "int128";
		}

		break;
	case XRG_PTYP_FP32:
		return is_array ? "float[]" : "float";
	case XRG_PTYP_FP64:
		return is_array ? "double[]" : "double";
	case XRG_PTYP_BYTEA:
		switch (ltyp) {
		case XRG_LTYP_STRING:
			return is_array ? "string[]" : "string";
		default:
			return is_array ? "bytea[]" : "bytea";
		}
		break;
	default:
		break;
	}

	return "";
}

Oid pg_array_to_element_oid(Oid t) {
	static Oid basic_type[] = {BOOLOID,
		INT2OID,
		INT4OID,
		INT8OID,
		DATEOID,
		TIMEOID,
		TIMESTAMPOID,
		TIMESTAMPTZOID,
		FLOAT4OID,
		FLOAT8OID,
		CASHOID,
		INTERVALOID,
		NUMERICOID,
		BPCHAROID, TEXTOID, VARCHAROID};

	static Oid array_type[] = {1000, // BOOLARRAYOID
		INT2ARRAYOID,
		INT4ARRAYOID,
		INT8ARRAYOID,
		1182, // DATEARRAYOID
		1183, // TIMEARRAYOID
		1115, // TIMESTAMPARRAYOID
		1185, // TIMESTAMPTZARRAYOID
		FLOAT4ARRAYOID,
		FLOAT8ARRAYOID,
		791,  // CASHARRAYOID
		1187, // INTERVALARRAYOID
		1231, // NUMERICARRAYOID
		1014, // BPCHARARRAY
		TEXTARRAYOID, 
		1015 // VARCHARARRAY
		};

	int narraytypes = sizeof(array_type) / sizeof(Oid);

	for (int i =  0 ; i < narraytypes ; i++) {
		if (array_type[i] == t) {
			return basic_type[i];
		}
	}

	return InvalidOid;
}

bool pg_typ_supported(Oid t, int32_t typmod, int32_t ndim) {
/*
	static Oid valid_type[] = {BOOLOID, 1000,
		INT2OID, INT2ARRAYOID,
		INT4OID, INT4ARRAYOID,
		INT8OID, INT8ARRAYOID,
		DATEOID, 1182,
		TIMEOID, 1183,
		TIMESTAMPOID, 1115,
		TIMESTAMPTZOID, 1185,
		FLOAT4OID, FLOAT4ARRAYOID,
		FLOAT8OID, FLOAT8ARRAYOID,
		CASHOID,
		INTERVALOID, 1187,
		NUMERICOID, 1231,
		BPCHAROID, TEXTOID, VARCHAROID, TEXTARRAYOID, 1014, 1015};
*/
	static Oid basic_type[] = {BOOLOID,
		INT2OID,
		INT4OID,
		INT8OID,
		DATEOID,
		TIMEOID,
		TIMESTAMPOID,
		TIMESTAMPTZOID,
		FLOAT4OID,
		FLOAT8OID,
		CASHOID,
		INTERVALOID,
		NUMERICOID,
		BPCHAROID, TEXTOID, VARCHAROID};

	static Oid array_type[] = {1000, // BOOLARRAYOID
		INT2ARRAYOID,
		INT4ARRAYOID,
		INT8ARRAYOID,
		1182, // DATEARRAYOID
		1183, // TIMEARRAYOID
		1115, // TIMESTAMPARRAYOID
		1185, // TIMESTAMPTZARRAYOID
		FLOAT4ARRAYOID,
		FLOAT8ARRAYOID,
		791,  // CASHARRAYOID
		1187, // INTERVALARRAYOID
		1231, // NUMERICARRAYOID
		1014, TEXTARRAYOID, 1015};

	int nbasictype = sizeof(basic_type) / sizeof(Oid);
	for (int i = 0; i < nbasictype; i++) {
		if (basic_type[i] == t) {
			return true;
		}
	}

	int narraytype = sizeof(array_type) / sizeof(Oid);
	for (int i = 0; i < narraytype; i++) {
		if (array_type[i] == t) {
			// HACK: CREATE EXTERNAL TABLE LIKE TBL -> ndim = 0
			// Therefore, We can only check ndim = 0 or 1 is valid.
			if (ndim == 0 || ndim == 1) {
				return true;
			}
			return false;
		}
	}
	return false;
}

void pg_typ_to_xrg_typ(Oid t, int32_t typmod, int16_t *ptyp, int16_t *ltyp, int16_t *precision, int16_t *scale, bool *is_array) {
	*is_array = false;
	switch (t) {
	case BOOLOID: {
		*ptyp = XRG_PTYP_INT8;
		*ltyp = XRG_LTYP_NONE;
	}
		return;
	case 1000: // array of BOOLOID
	{
		*ptyp = XRG_PTYP_INT8;
		*ltyp = XRG_LTYP_NONE;
		*is_array = true;
	}
		return;
	case INT2OID: {
		*ptyp = XRG_PTYP_INT16;
		*ltyp = XRG_LTYP_NONE;
	}
		return;
	case INT2ARRAYOID: {
		*ptyp = XRG_PTYP_INT16;
		*ltyp = XRG_LTYP_NONE;
		*is_array = true;
	}
		return;
	case INT4OID: {
		*ptyp = XRG_PTYP_INT32;
		*ltyp = XRG_LTYP_NONE;
	}
		return;
	case INT4ARRAYOID: {
		*ptyp = XRG_PTYP_INT32;
		*ltyp = XRG_LTYP_NONE;
		*is_array = true;
	}
		return;
	case INT8OID: {
		*ptyp = XRG_PTYP_INT64;
		*ltyp = XRG_LTYP_NONE;
	}
		return;
	case INT8ARRAYOID: {
		*ptyp = XRG_PTYP_INT64;
		*ltyp = XRG_LTYP_NONE;
		*is_array = true;
	}
		return;
	case DATEOID: {
		*ptyp = XRG_PTYP_INT32;
		*ltyp = XRG_LTYP_DATE;
	}
		return;
	case 1182: // array of date
	{
		*ptyp = XRG_PTYP_INT32;
		*ltyp = XRG_LTYP_DATE;
		*is_array = true;
	}
		return;
	case TIMEOID: {
		*ptyp = XRG_PTYP_INT64;
		*ltyp = XRG_LTYP_TIME;
	}
		return;
	case 1183: // array of time
	{
		*ptyp = XRG_PTYP_INT64;
		*ltyp = XRG_LTYP_TIME;
		*is_array = true;
	}
		return;
	case TIMESTAMPOID: {
		*ptyp = XRG_PTYP_INT64;
		*ltyp = XRG_LTYP_TIMESTAMP;
	}
		return;
	case 1115: // array of timestamp
	{
		*ptyp = XRG_PTYP_INT64;
		*ltyp = XRG_LTYP_TIMESTAMP;
		*is_array = true;
	}
		return;
	case TIMESTAMPTZOID: {
		*ptyp = XRG_PTYP_INT64;
		*ltyp = XRG_LTYP_TIMESTAMP;
	}
		return;
	case 1185: // array of timestamptz
	{
		*ptyp = XRG_PTYP_INT64;
		*ltyp = XRG_LTYP_TIMESTAMP;
		*is_array = true;
	}
		return;
	case FLOAT4OID: {
		*ptyp = XRG_PTYP_FP32;
		*ltyp = XRG_LTYP_NONE;
	}
		return;
	case FLOAT4ARRAYOID: {
		*ptyp = XRG_PTYP_FP32;
		*ltyp = XRG_LTYP_NONE;
		*is_array = true;
	}
		return;
	case FLOAT8OID: {
		*ptyp = XRG_PTYP_FP64;
		*ltyp = XRG_LTYP_NONE;
	}
		return;
	case FLOAT8ARRAYOID: {
		*ptyp = XRG_PTYP_FP64;
		*ltyp = XRG_LTYP_NONE;
		*is_array = true;
	}
		return;
	case CASHOID: {
		*ptyp = XRG_PTYP_INT128;
		*ltyp = XRG_LTYP_DECIMAL;
	}
		return;
	// case UUIDOD:
	// case 2951: // Array of UUID
	case INTERVALOID: {
		*ptyp = XRG_PTYP_INT128;
		*ltyp = XRG_LTYP_INTERVAL;
	}
		return;
	case 1187: // array of interval
	{
		*ptyp = XRG_PTYP_INT128;
		*ltyp = XRG_LTYP_INTERVAL;
		*is_array = true;
	}
		return;
	case NUMERICOID: {
		// Const will have typmod == -1. Set it to INT64 decimal first.
		*ptyp = XRG_PTYP_INT64;
		if (typmod >= (int32)VARHDRSZ) {
			int32_t tmp = typmod - VARHDRSZ;
			*precision = (tmp >> 16) & 0xFFFF;
			*scale = tmp & 0xFFFF;

			if (*precision <= 18) {
				*ptyp = XRG_PTYP_INT64;
			} else {
				*ptyp = XRG_PTYP_INT128;
			}
		}
		*ltyp = XRG_LTYP_DECIMAL;
	}
		return;
	case 1231: // array of NUMERIC
	{
		*ptyp = XRG_PTYP_INT64;
		*ltyp = XRG_LTYP_DECIMAL;
		*is_array = true;
		if (typmod >= (int32)VARHDRSZ) {
			int32_t tmp = typmod - VARHDRSZ;
			*precision = (tmp >> 16) & 0xFFFF;
			*scale = tmp & 0xFFFF;

			if (*precision <= 18) {
				*ptyp = XRG_PTYP_INT64;
			} else {
				*ptyp = XRG_PTYP_INT128;
			}
		}
	}
		return;
	case BYTEAOID: {
		*ptyp = XRG_PTYP_BYTEA;
		*ltyp = XRG_LTYP_NONE;
	}
		return;
	case BPCHAROID:
	case TEXTOID:
	case VARCHAROID: {
		*ptyp = XRG_PTYP_BYTEA;
		*ltyp = XRG_LTYP_STRING;
	}
		return;
	case TEXTARRAYOID:
	case 1014: // array of bpchar
	case 1015: // arrayof varchar
	{
		*ptyp = XRG_PTYP_BYTEA;
		*ltyp = XRG_LTYP_STRING;
		*is_array = true;
	}
		return;
	default: {
		*ptyp = XRG_PTYP_BYTEA;
		*ltyp = XRG_LTYP_STRING;
	}
		return;
	}
}

bool pg_typ_match_xrg_typ(Oid pgtyp, int32_t typmod, int16_t ptyp, int16_t ltyp) {
	if (pgtyp == 2281) {
		// PGTYPE == INTERNAL, XRG should be INT128/DECIMAL for SUM
		if ((ltyp == XRG_LTYP_NONE && ptyp == XRG_PTYP_INT128) || ltyp == XRG_LTYP_DECIMAL) {
			return true;
		}
		return false;
	}

	int16_t pg_ptyp, pg_ltyp, pg_precision, pg_scale;
	bool is_array = false;
	pg_typ_to_xrg_typ(pgtyp, typmod, &pg_ptyp, &pg_ltyp, &pg_precision, &pg_scale, &is_array);

	if (pg_ptyp == ptyp && pg_ltyp == ltyp) {
		return true;
	}

	return false;
}

static bool op_is_time_related(Oid oid) {
	// See sarg_info.i.cpp on what are these.
	switch (oid) {
	case 1093:
	case 1095:
	case 1096:
	case 1097:
	case 1098:
	case 1108:
	case 1110:
	case 1111:
	case 1112:
	case 1113:
	case 1320:
	case 1322:
	case 1323:
	case 1324:
	case 1325:
	case 2060:
	case 2062:
	case 2063:
	case 2064:
	case 2065:
		return true;
	}
	return false;
}


static void pg_typ_to_string(StringInfo str, Oid t, int32_t typmod) {
    switch (t) {
    case BOOLOID: {
		appendStringInfoString(str, "bool");
        return;
	}
    case 1000: // array of BOOLOID
	{
		appendStringInfoString(str, "bool[]");
        return;
	}
    case INT2OID: {
		appendStringInfoString(str, "int2");
        return;
	}
    case INT2ARRAYOID: {
		appendStringInfoString(str, "int2[]");
        return;
	}
    case INT4OID: {
		appendStringInfoString(str, "int4");
        return;
	}
    case INT4ARRAYOID: {
		appendStringInfoString(str, "int4[]");
        return;
	}
    case INT8OID: {
		appendStringInfoString(str, "int8");
        return;
	}
    case INT8ARRAYOID: {
		appendStringInfoString(str, "int8[]");
        return;
	}
    case DATEOID: {
		appendStringInfoString(str, "date");
        return;
    }
    case 1182: // array of date
    {
		appendStringInfoString(str, "date[]");
        return;
    }
    case TIMEOID: {
		appendStringInfoString(str, "time");
        return;
	}
    case 1183: // array of time
    {
		appendStringInfoString(str, "time[]");
        return;
    }
    case TIMESTAMPOID: {
		appendStringInfoString(str, "timestamp");
        return;
    }
    case 1115: // array of timestamp
    {
		appendStringInfoString(str, "timestamp[]");
        return;
    }
    case TIMESTAMPTZOID: {
		appendStringInfoString(str, "timestamp");
        return;
    }
    case 1185: // array of timestamptz
    {
		appendStringInfoString(str, "timestamp[]");
        return;
    }
    case FLOAT4OID: {
		appendStringInfoString(str, "real");
        return;
    }
    case FLOAT4ARRAYOID: {
		appendStringInfoString(str, "real[]");
        return;
    }
    case FLOAT8OID: {
		appendStringInfoString(str, "double precision");
        return;
    }
    case FLOAT8ARRAYOID: {
		appendStringInfoString(str, "double precision[]");
        return;
    }
    // case UUIDOD:
    // case 2951: // Array of UUID
    case INTERVALOID: {
		appendStringInfoString(str, "interval");
        return;
    }
    case 1187: // array of interval
    {
		appendStringInfoString(str, "interval[]");
        return;
    }
    case NUMERICOID: {
        // Const will have typmod == -1. Set it to INT64 decimal first.
        int precision = 0;
        int scale = 0;
        if (typmod >= (int32)VARHDRSZ) {
            int32_t tmp = typmod - VARHDRSZ;
            precision = (tmp >> 16) & 0xFFFF;
            scale = tmp & 0xFFFF;
        }
        appendStringInfo(str, "numeric(%d,%d)", precision, scale);
        return;
    }
    case 1231: // array of NUMERIC
    {
        int precision = 0;
        int scale = 0;
        if (typmod >= (int32)VARHDRSZ) {
            int32_t tmp = typmod - VARHDRSZ;
            precision = (tmp >> 16) & 0xFFFF;
            scale = tmp & 0xFFFF;
        }
        appendStringInfo(str, "numeric(%d,%d)[]", precision, scale);
        return;
    }
    case BPCHAROID:
    case TEXTOID:
    case VARCHAROID: {
		appendStringInfo(str, "text");
        return;
    }
    case TEXTARRAYOID:
    case 1014: // array of bpchar
    case 1015: // arrayof varchar
    {
		appendStringInfo(str, "text[]");
        return;
    }
    default: {
		appendStringInfo(str, "text");
        return;
    }
  }
}

static void date_to_string(StringInfo str, int32_t d) {
	struct tm tm;
	time_t t = d * 24 * 3600;
	gmtime_r(&t, &tm);

	appendStringInfo(str, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

static void timestamp_to_string(StringInfo str, int64_t ts) {
	struct tm tm;
	time_t t = ts / 1000000;
	int usecs = ts % 1000000;
	gmtime_r(&t, &tm);

	appendStringInfo(str, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
		tm.tm_min, tm.tm_sec, usecs);
}

static void interval_to_string(StringInfo str, __int128_t interval) {
	uint64_t *pi64 = (uint64_t *)&interval;
	uint32_t *pi32 = (uint32_t *)&pi64[1];
	uint32_t months = pi32[1];
	uint32_t days = pi32[0];

	appendStringInfo(str, "%d mons %d days %" PRId64 " microseconds", months, days, pi64[0]);
}

static void time_to_string(StringInfo str, int64_t ts) {
	time_t secs = ts / 1000000;
	int usecs = ts % 1000000;
	struct tm tm;
	gmtime_r(&secs, &tm);

	appendStringInfo(str, "%02d:%02d:%02d.%06d",
		tm.tm_hour, tm.tm_min, tm.tm_sec, usecs);
}

static inline void int32_to_string(StringInfo str, int32_t i32) {
	appendStringInfo(str, "%d", i32);
}

static inline void int64_to_string(StringInfo str, int64_t i64) {
	appendStringInfo(str, "%" PRId64, i64);
}

static inline void double_to_string(StringInfo str, double f64) {
	appendStringInfo(str, "%f", f64);
}

char *op_sarg_const_str(const char *ts, Datum d, int *plen) {
	StringInfoData str;
	initStringInfo(&str);

#ifdef HAVE_INT64_TIMESTAMP
	Timestamp epoch_ts = SetEpochTimestamp();
#endif
	if (strcmp(ts, "int8") == 0) {
		int8_t i = DatumGetInt8(d);
		int32_to_string(&str, i);
		return str.data;
	}
	if (strcmp(ts, "int16") == 0) {
		int16_t i = DatumGetInt16(d);
		int32_to_string(&str, i);
		return str.data;
	}
	if (strcmp(ts, "int32") == 0) {
		int32_t i = DatumGetInt32(d);
		int32_to_string(&str, i);
		return str.data;
	}
	if (strcmp(ts, "int64") == 0) {
		int64_t i = (int64_t)d;
		int64_to_string(&str, i);
		return str.data;
	}
	if (strcmp(ts, "fp32") == 0 || strcmp(ts, "float32") == 0 || strcmp(ts, "float") == 0) {
		float f = DatumGetFloat4(d);
		double_to_string(&str, f);
		return str.data;
	}
	if (strcmp(ts, "fp64") == 0 || strcmp(ts, "float64") == 0 || strcmp(ts, "double") == 0) {
		double f = DatumGetFloat8(d);
		double_to_string(&str, f);
		return str.data;
	}
	if (strcmp(ts, "date") == 0) {
		int32_t i = DatumGetInt32(d);
		i += (POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE);
		date_to_string(&str, i);
		return str.data;
	}
	if (strcmp(ts, "time") == 0) {
		int64_t i = (int64_t)d;
		time_to_string(&str, i);
		return str.data;
	}
	if (strcmp(ts, "timestamp") == 0 || strcmp(ts, "timestamp_micros") == 0) {
		int64_t i = (int64_t)d;
		timestamp_to_string(&str, i - epoch_ts);
		return str.data;
	}
	if (strcmp(ts, "timestamptz") == 0 || strcmp(ts, "timestamptz_micros") == 0) {
		int64_t i = (int64_t)d;
		timestamp_to_string(&str, i - epoch_ts);
		return str.data;
	}
	if (strcmp(ts, "interval") == 0) {
		__int128 interval = *((__int128 *)DatumGetPointer(d));
		interval_to_string(&str, interval);
		return str.data;
	}
	if (strcmp(ts, "decimal") == 0) {
		return DatumGetCString(DirectFunctionCall1(numeric_out, d));
	}
	if (strcmp(ts, "uuid") == 0) {
		return DatumGetCString(DirectFunctionCall1(uuid_out, d));
	}
	if (strcmp(ts, "inet") == 0) {
		inet *pi = DatumGetInetPP(d);
		inet_struct *pis = (inet_struct *)VARDATA_ANY(pi);
		int pissz = 6;
		if (pis->family == PGSQL_AF_INET6) {
			pissz = 18;
		}
		char buf[36];
		hex_encode((const char *)pis, pissz, buf);
		char *ret = (char *)palloc(pissz * 2 + 1);
		memcpy(ret, buf, pissz * 2);
		ret[pissz * 2] = 0;
		return ret;
	}
	if (strcmp(ts, "macaddr") == 0) {
		const char *pm = (const char *)DatumGetPointer(d);
		char buf[12];
		hex_encode(pm, 6, buf);
		char *ret = (char *)palloc(12 + 1);
		memcpy(ret, buf, 12);
		ret[12] = 0;
		return ret;
	}
	if (strcmp(ts, "text") == 0 || strcmp(ts, "string") == 0) {

		if (plen) {
			//
			// This must comes from the array case.   Greenplum has an optimization for
			// IN ('A', 'B', 'C').   Instead of the usual way of calling functions, it
			// record the string and len, so that a memcpy is used directly.  In this case,
			// d is a pointer to the string (not null terminated, but use plen), not a text.
			// string escaped by double single-qouted
			char *pstr = (char *)DatumGetPointer(d);
			for (int i = 0; i < *plen; i++) {
				if (pstr[i] == '\'') {
					appendStringInfoString(&str, "''");
				} else {
					appendStringInfoCharMacro(&str, pstr[i]);
				}
			}
		} else if (strcmp(ts, "text") == 0) {
			text *t = DatumGetTextPP(d);
			int32_t len = VARSIZE_ANY_EXHDR(t);
			char *data = VARDATA_ANY(t);
			for (int i = 0; i < len; i++) {
				if (data[i] == '\'') {
					appendStringInfoCharMacro(&str, '\'');
				}
				appendStringInfoCharMacro(&str, data[i]);
			}
		} else {
			for (char *pstr = (char *)DatumGetPointer(d); *pstr; pstr++) {
				if (*pstr == '\'') {
					appendStringInfoString(&str, "''");
				} else {
					appendStringInfoCharMacro(&str, *pstr);
				}
			}
		}

		return str.data;
	}

	return 0;
}


#if 1
const char *op_arraytype_to_string(Const *c) {
	int16_t ptyp, ltyp, precision, scale;
	bool is_array = false;
	pg_typ_to_xrg_typ(c->consttype, c->consttypmod, &ptyp, &ltyp, &precision, &scale, &is_array);
	Insist(is_array == true);

	FmgrInfo flinfo;
	memset(&flinfo, 0, sizeof(FmgrInfo));
	//fmgr_info_cxt(fmgr_internal_function("array_out"), &flinfo, CurrentMemoryContext);
	flinfo.fn_mcxt = CurrentMemoryContext;
	flinfo.fn_addr = array_out;
	flinfo.fn_nargs = 1;
	flinfo.fn_strict = true;
	char *array = OutputFunctionCall(&flinfo, c->constvalue);
	StringInfoData qual;
	initStringInfo(&qual);
	appendStringInfo(&qual, "'%s'", array);
	appendStringInfoString(&qual, "::");
	pg_typ_to_string(&qual, c->consttype, c->consttypmod);
	return qual.data;
}

#else

const char *op_arraytype_to_string(Const *c) {
#ifdef HAVE_INT64_TIMESTAMP
	Timestamp epoch_ts = SetEpochTimestamp();
#endif

	int16_t ptyp, ltyp, precision, scale;
	bool is_array = false;
	ptyp = ltyp = precision = scale = 0;
	ArrayType *arr = DatumGetArrayTypeP(c->constvalue);
	int numargs = ARR_DIMS(arr)[0];
	int ndim = ARR_NDIM(arr);
	//int elemtype = ARR_ELEMTYPE(arr);
	//int offset = ARR_DATA_OFFSET(arr);

	pg_typ_to_xrg_typ(c->consttype, c->consttypmod, &ptyp, &ltyp, &precision, &scale, &is_array);
	size_t itemsz = xrg_typ_size(ptyp);
	const char *xrg_typ = xrg_typ_str(ptyp, ltyp, false); // only want to get primitive type
	Insist(xrg_typ && *xrg_typ != 0 && is_array == true);

	StringInfoData qual;
	initStringInfo(&qual);

	if (ndim == 0) {
		appendStringInfoString(&qual, "ARRAY[]::");
		pg_typ_to_string(&qual, c->consttype, c->consttypmod);
		return qual.data;
	}

	if (ndim != 1) {
		elog(ERROR, "dimension of constant array must be 1");
	}

	if (strcmp(xrg_typ, "string") == 0 && c->constlen == -1) {
		xrg_typ = "text";
	}

	bool hasnull = ARR_HASNULL(arr);
	bits8* nullmap = ARR_NULLBITMAP(arr);
	char *p = (char *)ARR_DATA_PTR(arr);
	int bitmask = 1;
	//elog(LOG, "numargs = %d, consttype = %d, constlen = %d", numargs, c->consttype, c->constlen);
	appendStringInfoString(&qual, "ARRAY");
	appendStringInfoCharMacro(&qual, '[');
	for (int i = 0; i < numargs; i++) {
		if (i > 0) {
			appendStringInfoCharMacro(&qual, ',');
		}
		if (nullmap && (*nullmap & bitmask) == 0) {
			appendStringInfoString(&qual, "NULL");
		} else {
			if (strcmp(xrg_typ, "text") == 0  || strcmp(xrg_typ, "string") == 0 || strcmp(xrg_typ, "decimal") == 0) {
				int32_t datalen = VARSIZE_ANY(p);
				//int32_t len = VARSIZE_ANY_EXHDR(p);
				//elog(LOG, "string: aligned = %d, datalen = %d len = %d, %s", INTALIGN(datalen), datalen, len, data);
				appendStringInfoCharMacro(&qual, '\'');
				// string escaped by the single quote
				appendStringInfoString(&qual, op_sarg_const_str(xrg_typ, (Datum)p, 0));
				appendStringInfoCharMacro(&qual, '\'');
				p += INTALIGN(datalen); // data is 4-byte aligned

			} else {
				if (strcmp(xrg_typ, "date") == 0) {
					appendStringInfoCharMacro(&qual, '\'');
					int32_t date = *((int32_t *)p) + (POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE);
					date_to_string(&qual, date);
					appendStringInfoCharMacro(&qual, '\'');
				} else if (strcmp(xrg_typ, "time") == 0) {
					appendStringInfoCharMacro(&qual, '\'');
					time_to_string(&qual, *((int64_t *)p));
					appendStringInfoCharMacro(&qual, '\'');
				} else if (strcmp(xrg_typ, "timestamp") == 0 || strcmp(xrg_typ, "timestamptz") == 0 ||
						   strcmp(xrg_typ, "timestamp_micros") == 0 || strcmp(xrg_typ, "timestamptz_micros") == 0) {
					appendStringInfoCharMacro(&qual, '\'');
					timestamp_to_string(&qual, *((int64_t *)p) - epoch_ts);
					appendStringInfoCharMacro(&qual, '\'');
				} else if (strcmp(xrg_typ, "int8") == 0) {
					int32_to_string(&qual, *((int8_t *)p));
				} else if (strcmp(xrg_typ, "int16") == 0) {
					int32_to_string(&qual, *((int16_t *)p));
				} else if (strcmp(xrg_typ, "int32") == 0) {
					int32_to_string(&qual, *((int32_t *)p));
				} else if (strcmp(xrg_typ, "int64") == 0) {
					int64_to_string(&qual, *((int64_t *)p));
				} else if (strcmp(xrg_typ, "fp32") == 0 || strcmp(xrg_typ, "float") == 0) {
					double_to_string(&qual, *((float *)p));
				} else if (strcmp(xrg_typ, "fp64") == 0 || strcmp(xrg_typ, "double") == 0) {
					double_to_string(&qual, *((double *)p));
				}

				p += itemsz;
			}
		}
		
		/* advance bitmap pointer if any */
		if (nullmap) {
			bitmask <<= 1;
			if (bitmask == 0x100 /* (1<<8) */) {
				nullmap++;
				bitmask = 1;
			}
		}
	}
	appendStringInfoCharMacro(&qual, ']');
	appendStringInfoString(&qual, "::");
	pg_typ_to_string(&qual, c->consttype, c->consttypmod);
	return qual.data;
}
#endif
