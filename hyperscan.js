const ref = require('ref');

const r = ref.refType;
const ffi = require('ffi');
const Struct = require('ref-struct');
const ArrayType = require('ref-array');
/**
 * Compile flag: Set case-insensitive matching.
 *
 * This flag sets the expression to be matched case-insensitively by default.
 * The expression may still use PCRE tokens (notably `(?i)` and
 * `(?-i)`) to switch case-insensitive matching on and off.
 */
const HS_FLAG_CASELESS = 1;

/**
 * Compile flag: Matching a `.` will not exclude newlines.
 *
 * This flag sets any instances of the `.` token to match newline characters as
 * well as all other characters. The PCRE specification states that the `.`
 * token does not match newline characters by default, so without this flag the
 * `.` token will not cross line boundaries.
 */
const HS_FLAG_DOTALL = 2;

/**
 * Compile flag: Set multi-line anchoring.
 *
 * This flag instructs the expression to make the `^` and `$` tokens match
 * newline characters as well as the start and end of the stream. If this flag
 * is not specified, the `^` token will only ever match at the start of a
 * stream, and the `$` token will only ever match at the end of a stream within
 * the guidelines of the PCRE specification.
 */
const HS_FLAG_MULTILINE = 4;

/**
 * Compile flag: Set single-match only mode.
 *
 * This flag sets the expression's match ID to match at most once. In streaming
 * mode, this means that the expression will return only a single match over
 * the lifetime of the stream, rather than reporting every match as per
 * standard Hyperscan semantics. In block mode or vectored mode, only the first
 * match for each invocation of @ref hs_scan() or @ref hs_scan_vector() will be
 * returned.
 *
 * If multiple expressions in the database share the same match ID, then they
 * either must all specify @ref HS_FLAG_SINGLEMATCH or none of them specify
 * @ref HS_FLAG_SINGLEMATCH. If a group of expressions sharing a match ID
 * specify the flag, then at most one match with the match ID will be generated
 * per stream.
 *
 * Note: The use of this flag in combination with @ref HS_FLAG_SOM_LEFTMOST
 * is not currently supported.
 */
const HS_FLAG_SINGLEMATCH = 8;

/**
 * Compile flag: Allow expressions that can match against empty buffers.
 *
 * This flag instructs the compiler to allow expressions that can match against
 * empty buffers, such as `.?`, `.*`, `(a|)`. Since Hyperscan can return every
 * possible match for an expression, such expressions generally execute very
 * slowly; the default behaviour is to return an error when an attempt to
 * compile one is made. Using this flag will force the compiler to allow such
 * an expression.
 */
const HS_FLAG_ALLOWEMPTY = 16;

/**
 * Compile flag: Enable UTF-8 mode for this expression.
 *
 * This flag instructs Hyperscan to treat the pattern as a sequence of UTF-8
 * characters. The results of scanning invalid UTF-8 sequences with a Hyperscan
 * library that has been compiled with one or more patterns using this flag are
 * undefined.
 */
const HS_FLAG_UTF8 = 32;

/**
 * Compile flag: Enable Unicode property support for this expression.
 *
 * This flag instructs Hyperscan to use Unicode properties, rather than the
 * default ASCII interpretations, for character mnemonics like `\w` and `\s` as
 * well as the POSIX character classes. It is only meaningful in conjunction
 * with @ref HS_FLAG_UTF8.
 */
const HS_FLAG_UCP = 64;

/**
 * Compile flag: Enable prefiltering mode for this expression.
 *
 * This flag instructs Hyperscan to compile an "approximate" version of this
 * pattern for use in a prefiltering application, even if Hyperscan does not
 * support the pattern in normal operation.
 *
 * The set of matches returned when this flag is used is guaranteed to be a
 * superset of the matches specified by the non-prefiltering expression.
 *
 * If the pattern contains pattern constructs not supported by Hyperscan (such
 * as zero-width assertions, back-references or conditional references) these
 * constructs will be replaced internally with broader constructs that may
 * match more often.
 *
 * Furthermore, in prefiltering mode Hyperscan may simplify a pattern that
 * would otherwise return a "Pattern too large" error at compile time, or for
 * performance reasons (subject to the matching guarantee above).
 *
 * It is generally expected that the application will subsequently confirm
 * prefilter matches with another regular expression matcher that can provide
 * exact matches for the pattern.
 *
 * Note: The use of this flag in combination with @ref HS_FLAG_SOM_LEFTMOST
 * is not currently supported.
 */
const HS_FLAG_PREFILTER = 128;

/**
 * Compile flag: Enable leftmost start of match reporting.
 *
 * This flag instructs Hyperscan to report the leftmost possible start of match
 * offset when a match is reported for this expression. (By default, no start
 * of match is returned.)
 *
 * Enabling this behaviour may reduce performance and increase stream state
 * requirements in streaming mode.
 */
const HS_FLAG_SOM_LEFTMOST = 256;

/**
 * Compiler mode flag: Block scan (non-streaming) database.
 */
const HS_MODE_BLOCK = 1;

/**
 * Compiler mode flag: Alias for @ref HS_MODE_BLOCK.
 */
const HS_MODE_NOSTREAM = 1;

/**
 * Compiler mode flag: Streaming database.
 */
const HS_MODE_STREAM = 2;

/**
 * Compiler mode flag: Vectored scanning database.
 */
const HS_MODE_VECTORED = 4;

/**
 * Compiler mode flag: use full precision to track start of match offsets in
 * stream state.
 *
 * This mode will use the most stream state per pattern, but will always return
 * an accurate start of match offset regardless of how far back in the past it
 * was found.
 *
 * One of the SOM_HORIZON modes must be selected to use the @ref
 * HS_FLAG_SOM_LEFTMOST expression flag.
 */
const HS_MODE_SOM_HORIZON_LARGE = 1 << 24;

/**
 * Compiler mode flag: use medium precision to track start of match offsets in
 * stream state.
 *
 * This mode will use less stream state than @ref HS_MODE_SOM_HORIZON_LARGE and
 * will limit start of match accuracy to offsets within 2^32 bytes of the
 * end of match offset reported.
 *
 * One of the SOM_HORIZON modes must be selected to use the @ref
 * HS_FLAG_SOM_LEFTMOST expression flag.
 */
const HS_MODE_SOM_HORIZON_MEDIUM = 1 << 25;

/**
 * Compiler mode flag: use limited precision to track start of match offsets in
 * stream state.
 *
 * This mode will use less stream state than @ref HS_MODE_SOM_HORIZON_LARGE and
 * will limit start of match accuracy to offsets within 2^16 bytes of the
 * end of match offset reported.
 *
 * One of the SOM_HORIZON modes must be selected to use the @ref
 * HS_FLAG_SOM_LEFTMOST expression flag.
 */
const HS_MODE_SOM_HORIZON_SMALL = 1 << 26;

/*
typedef struct hs_platform_info {
    **
     * Information about the target platform which may be used to guide the
     * optimisation process of the compile.
     *
     * Use of this field does not limit the processors that the resulting
     * database can run on, but may impact the performance of the resulting
     * database.
     *
    unsigned int tune;

    **
     * Relevant CPU features available on the target platform
     *
     * This value may be produced by combining HS_CPU_FEATURE_* flags (such as
     * @ref HS_CPU_FEATURES_AVX2). Multiple CPU features may be or'ed together
     * to produce the value.
     *
    unsigned long long cpu_features;

    // Reserved for future use.
    unsigned long long reserved1;

    // Reserved for future use.
    unsigned long long reserved2;
} hs_platform_info_t;
*/
const hsPlatformInfo = Struct({
  tune: 'uint',
  cpu_features: 'ulonglong', // could use a ref-bitfield here, but no need to atm.
  reserved1: 'ulonglong',
  reserved2: 'ulonglong'
});

/*
struct hs_database {
    u32 magic;
    u32 version;
    u32 length;
    u64a platform;
    u32 crc32;
    u32 reserved0;
    u32 reserved1;
    u32 bytecode;    // offset relative to db start
    u32 padding[16];
    char bytes[];
};
*/
// we cannot (and wont) make any attempt at deseriaizing databases
const hsDatabase = r(ref.types.void);
// same goes for scratch
const hsScratch = r(ref.types.void);

/**
 * Definition of the match event callback function type.
 *
 * A callback function matching the defined type must be provided by the
 * application calling the @ref hsScan(), @ref hsScanVector() or @ref
 * hsScanStream() functions (or other streaming calls which can produce
 * matches).
 *
 * This callback function will be invoked whenever a match is located in the
 * target data during the execution of a scan. The details of the match are
 * passed in as parameters to the callback function, and the callback function
 * should return a value indicating whether or not matching should continue on
 * the target data. If no callbacks are desired from a scan call, NULL may be
 * provided in order to suppress match production.
 *
 * This callback function should not attempt to call Hyperscan API functions on
 * the same stream nor should it attempt to reuse the scratch space allocated
 * for the API calls that caused it to be triggered. Making another call to the
 * Hyperscan library with completely independent parameters should work (for
 * example, scanning a different database in a new stream and with new scratch
 * space), but reusing data structures like stream state and/or scratch space
 * will produce undefined behavior.
 *
 * It will be called with a single argument 'null' if no matches are found in a
 * particular data set.
 *
 * @param {unsigned int?} id
 *      The ID number of the expression that matched. If the expression was a
 *      single expression compiled with @ref hs_compile(), this value will be
 *      zero.
 *
 * @param {unsigned long long} from
 *      - If a start of match flag is enabled for the current pattern, this
 *        argument will be set to the start of match for the pattern assuming
 *        that that start of match value lies within the current 'start of match
 *        horizon' chosen by one of the SOM_HORIZON mode flags.

 *      - If the start of match value lies outside this horizon (possible only
 *        when the SOM_HORIZON value is not @ref HS_MODE_SOM_HORIZON_LARGE),
 *        the @a from value will be set to @ref HS_OFFSET_PAST_HORIZON.

 *      - This argument will be set to zero if the Start of Match flag is not
 *        enabled for the given pattern.
 *
 * @param {unsigned long long} to
 *      The offset after the last byte that matches the expression.
 *
 * @param {unsigned int} flags
 *      This is provided for future use and is unused at present.
 *
 * @param {void*} context
 *      The pointer supplied by the user to the @ref hs_scan(), @ref
 *      hs_scan_vector() or @ref hs_scan_stream() function.
 *
 * @return {int}
 *      Non-zero if the matching should cease, else zero. If scanning is
 *      performed in streaming mode and a non-zero value is returned, any
 *      subsequent calls to @ref hs_scan_stream() for that stream will
 *      immediately return with @ref HS_SCAN_TERMINATED.
 */
function matchEventHandler(id, from, to, flags, context) {} // eslint-disable-line no-unused-vars

/**
 * Creates a hyperscan match event handler
 * @param {matchEventHandler} callback
 * @returns {ffi.Callback} The generated callback
 */
function hsMatchEventHandler(callback) {
  return ffi.Callback('int', ['uint', 'uint64', 'uint64', 'uint', r(ref.types.void)], callback);
}


/**
@typedef hs_compile_error {
    **
     * A human-readable error message describing the error.
     *
    char *message;

    **
     * The zero-based number of the expression that caused the error (if this
     * can be determined). If the error is not specific to an expression, then
     * this value will be less than zero.
     *
    int expression;
} hs_compile_error_t;
*/
const hsCompileError = Struct({
  message: 'string',
  expression: 'int'
});


const hyperscan = ffi.Library('libhs.so', {
//  hs_error_t hs_compile(
//   const char * expression,
//   unsigned int flags,
//   unsigned int mode,
//   const hs_platform_info_t * platform,
//   hs_database_t ** db,
//   hs_compile_error_t ** error)
  hs_compile: ['int', [
    'string' /* expression */,
    'uint' /* flags */,
    'uint' /* mode */,
    r(hsPlatformInfo) /* platform */,
    r(hsDatabase) /* db */,
    r(r(hsCompileError)) /*  error */
  ]],
  /*
  hs_error_t hs_compile_multi(const char *const * expressions,
    const unsigned int * flags,
    const unsigned int * ids,
    unsigned int elements,
    unsigned int mode,
    const hs_platform_info_t * platform,
    hs_database_t ** db,
    hs_compile_error_t ** error)
  */
  hs_compile_multi: ['int', [
    ArrayType('string') /* expressions */,
    ArrayType('uint') /* flags */,
    ArrayType('uint') /* ids */,
    'uint' /* elements */,
    'uint' /* mode */,
    r(hsPlatformInfo) /* platform */,
    r(hsDatabase) /* db */,
    r(r(hsCompileError)) /*  error */
  ]],
  hs_scan: ['int', [
    hsDatabase /* db */,
    'string' /* data */,
    'uint' /* length */,
    'uint' /* flags */,
    hsScratch /* scratch */,
    'pointer' /* onEvent */,
    r(ref.types.void) /* context */
  ]],
  hs_alloc_scratch: ['int', [
    hsDatabase /* db */,
    r(hsScratch) /* scratch */
  ]],
  hs_database_info: ['int', [
    hsDatabase /* db */,
    r(ref.types.CString) /* info */
  ]]
});
/*
var dbPtrPtr = ref.alloc(r(hsDatabase));
var errPtrPtr = ref.alloc(r(r(hsCompileError)));
var platformPtr = ref.alloc(r(hsPlatformInfo));
var res = hyperscan.hs_compile("Hello World!", HS_FLAG_CASELESS, HS_MODE_BLOCK, ref.NULL, dbPtrPtr, errPtrPtr);
console.log("Result: "+res);
if(ref.isNull(errPtrPtr.deref())) console.log("No error");
else console.log("Error message: "+errPtrPtr.deref().deref());
hsDatabaseInfo(dbPtrPtr.deref());

console.log("-------------------------")
*/

/**
 * Allocates a scratch object for a database
 * @param {hsDatabase} db The database for which to allocate a scratch
 * @returns {hsScratch} Allocated scratch object
 */
function hsAllocScratch(db) {
  const scratchPtrPtr = ref.alloc(r(hsScratch), ref.NULL);
  const res = hyperscan.hs_alloc_scratch(db, scratchPtrPtr);
  console.log('Scratch allocation result:', res);
  // console.log(scratchPtrPtr);
  return scratchPtrPtr.deref();
}

/**
 * Compiles a single pattern into a database
 * @param {String} pattern A pattern to compile
 * @param {int} flags Matching flags (see HS_FLAG_...)
 * @param {int} mode Match modes (see HS_MODE_...)
 * @return {hsDatabase} The newly generated database
 */
function hsCompile(pattern, flags, mode) {
  const dbPtrPtr = ref.alloc(r(hsDatabase));
  const errPtrPtr = ref.alloc(r(hsCompileError));
  const res = hyperscan.hs_compile(pattern, flags || (HS_FLAG_CASELESS | HS_FLAG_SOM_LEFTMOST), mode || (HS_MODE_BLOCK), ref.NULL, dbPtrPtr, errPtrPtr);
  if (res !== 0) {
    const err = errPtrPtr.deref().deref();
    throw new Error(`Pattern compilation error: ${err.message} for pattern '${pattern}' with the ID ${err.expression}`);
  } else {
    return dbPtrPtr.deref();
  }
}

/**
 * Compile multiple patterns into a pattern database
 * @param {Array<{pattern: String, flags: int}>} patterns A list of strings or objects {pattern: String, flags: int} specifying the patterns and flags to use for each regex.
 * defaultFlags is used for each pattern that doesnt have a flag set explicitely.
 * @param {int} defaultFlags Flags (see HS_FLAG_...) to be used for patterns that do not explicitely overwrite the flags.
 * @param {int} mode Matching modes (see HS_MODE_...)
 */
function hsCompileMany(patterns, defaultFlags, mode) {
  const dbPtrPtr = ref.alloc(r(hsDatabase));
  const errPtrPtr = ref.alloc(r(hsCompileError));

  const patternList = [];
  const flagList = [];
  const idList = [];

  defaultFlags = defaultFlags || (HS_FLAG_CASELESS | HS_FLAG_SOM_LEFTMOST);
  patterns.forEach((value, index) => {
    if (!value) throw new Error('Invalid pattern', value);
    if (typeof (value) === 'string') {
      patternList.push(value);
      flagList.push(defaultFlags);
    } else {
      if (!value.pattern || typeof (value.pattern) !== 'string') throw new Error('Invalid pattern', value.pattern);
      patternList.push(value.pattern);
      flagList.push(value.pattern || defaultFlags);
    }
    idList.push(index);
  });

  const res = hyperscan.hs_compile_multi(patternList, flagList, idList, patterns.length, mode || (HS_MODE_BLOCK), ref.NULL, dbPtrPtr, errPtrPtr);
  if (res !== 0) {
    const err = errPtrPtr.deref().deref();
    throw new Error(`Pattern compilation error: ${err.message} for pattern '${pattern}' with the ID ${err.expression}`);
  } else {
    return dbPtrPtr.deref();
  }
}

/**
 * Scans a string for matches. Calls the specified match event handler once a match is found. If no matches are found, the callback is called once with a single argument 'null'
 * @param {hsDatabase} db The database to use
 * @param {String} data The string to scan
 * @param {matchEventHandler} callback The callback to run when a match is found
 * @param {hsScratch} scratch A scratch to use for matching
 * @param {*} context
 */
function hsScan(db, data, callback, scratch, context) {
  scratch = scratch || hsAllocScratch(db);
  let matchFound = false;
  const res = hyperscan.hs_scan(db, data, Buffer.byteLength(data), 0, scratch, hsMatchEventHandler((id, fromIdx, toIdx, flags, contextPtr) => {
    // console.log(`Match found! id: ${id}, from: ${fromIdx}, to: ${toIdx}, flags: ${flags}, context: ${contextPtr}`)
    // console.log(contextPtr);
    matchFound = true;
    callback(id, fromIdx, toIdx, flags, contextPtr);
    return 0;
  }), context);
  console.log(`hs_scan result: ${res}`);
  if (!matchFound) callback(null);
}

/**
 * Not implemented yet.
 */
function hsScanVector(db, data, length, count, flags, onMatch, scratch) {

}

/**
 * Not implemented yet.
 */
function hsScanStream() {

}

/**
 * Returns information about a database
 * @param {hsDatabase} db
 */
function hsDatabaseInfo(db) {
  const info = ref.alloc(r(ref.types.CString));
  const res = hyperscan.hs_database_info(db, info);
  // console.log("Info result: "+res);
  return info.deref().readCString(0);
}

/**
 *
 * @param {hsDatabase} db
 * @param {String} data
 * @param {matchEventHandler} onMatch
 * @param {hsScratch} scratch
 */
function hsScanAsync(db, data, onMatch, scratch) {
  scratch = scratch || hsAllocScratch(db);
  let matchFound = false;
  return new Promise((r, j) => {
    const res = hyperscan.hs_scan.async(db, data, Buffer.byteLength(data), 0, scratch, hsMatchEventHandler((id, fromIdx, toIdx, flags, contextPtr) => {
      // console.log(`Match found! id: ${id}, from: ${fromIdx}, to: ${toIdx}, flags: ${flags}, context: ${contextPtr}`)
      // console.log(contextPtr);
      matchFound = true;
      onMatch(id, fromIdx, toIdx, flags, contextPtr);
      return 0;
    }), null, (err, res) => {
      if (err) j(err);
      else {
        r(res);
      }
    });
  });
}

module.exports = {
  HS_FLAG_ALLOWEMPTY,
  HS_FLAG_CASELESS,
  HS_FLAG_DOTALL,
  HS_FLAG_MULTILINE,
  HS_FLAG_PREFILTER,
  HS_FLAG_SINGLEMATCH,
  HS_FLAG_SOM_LEFTMOST,
  HS_FLAG_UCP,
  HS_FLAG_UTF8,
  HS_MODE_BLOCK,
  HS_MODE_NOSTREAM,
  HS_MODE_STREAM,
  HS_MODE_VECTORED,
  HS_MODE_SOM_HORIZON_LARGE,
  HS_MODE_SOM_HORIZON_MEDIUM,
  HS_MODE_SOM_HORIZON_SMALL,
  hsCompile,
  hsCompileMany,
  hsScan,
  hsScanAsync
};
