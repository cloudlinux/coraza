// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type jsonBodyProcessor struct{}

var _ plugintypes.BodyProcessor = &jsonBodyProcessor{}

func (js *jsonBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, bpo plugintypes.BodyProcessorOptions) error {
	// Read the entire body into memory for two purposes:
	// 1. Store raw JSON in TX variables for operators like @validateSchema
	// 2. Parse and flatten for ARGS_POST collection
	s := strings.Builder{}
	if _, err := io.Copy(&s, reader); err != nil {
		return err
	}
	ss := s.String()

	// Store the raw JSON in the TX variable for validateSchema before parsing,
	// so operators like @validateSchema keep their data even when parsing stops
	// early on the argument limit or the recursion-depth limit.
	// This is needed because RequestBody is a Single interface without a Set method
	if txVar := v.TX(); txVar != nil {
		txVar.Set("json_request_body", []string{ss})
	}

	// Process with recursion limit
	col := v.ArgsPost()
	data, err := readJSON(ss, bpo.RequestBodyRecursionLimit, bpo.ArgumentLimit)
	if err != nil && !errors.Is(err, ErrArgumentsLimit) {
		return err
	}
	for key, value := range data {
		col.SetIndex(key, 0, value)
	}

	return err
}

const ignoreJSONRecursionLimit = -1

// jsonDecodedBytesSlack is the largest allowance added to the body length to
// form the budget of decoded bytes (flattened keys plus values) a JSON body
// may produce. Every leaf is stored under its full path
// ("json.<k1>.<k2>...<kn>.leaf"), so a body that nests deeply and then fans
// out makes many leaves share one long prefix: stored bytes grow with
// depth * leaves while the body grows only with depth + leaves. Neither the
// argument count nor the body length sees that product, so it is bounded
// directly. Deriving the budget from the body keeps it self-tuning: a
// legitimate body decodes to roughly its own size plus one path prefix per
// member, and the slack covers that overhead outright, while the amplifying
// shapes overshoot it by one to two orders of magnitude.
const jsonDecodedBytesSlack = 1 << 20

// jsonDecodedBytesScale caps the slack a small body earns. A fixed slack is a
// fixed amount of amplification every request may buy however small it is, and
// a body of a couple of kilobytes can spend it entirely on one long shared path
// prefix: that costs no memory worth the name but feeds every member through
// each ARGS rule's transformation pipeline, so a 2 KB request can cost more
// phase 2 CPU than a legitimate one of a megabyte. Tying the slack to the body
// for small inputs keeps that cost proportional to what was actually sent.
const jsonDecodedBytesScale = 64

// MaxEntriesPerArgument bounds the array-length entries a JSON body may store
// for each argument it is allowed. Scalars are capped by the argument limit
// directly, but the length entry recorded for a non-empty array is not an
// argument ModSecurity counts and so spends no argument budget: a chain of
// nested arrays costs one argument and stores one member per level. The
// decoded-bytes budget cannot stand in for this bound, because a length entry
// costs only its key and because inter-token whitespace raises a budget derived
// from the body length without storing anything, so the entries are counted
// directly. Counting them rather than the size of the whole collection keeps
// this budget independent of the argument count, so the arguments a body
// carries cannot change the verdict on its arrays. Together with the argument
// limit it holds a body to MaxEntriesPerArgument+1 stored members per argument
// allowed.
const MaxEntriesPerArgument = 2

// ErrJSONDecodedSize is raised when storing an entry would push a body past its
// decoded-bytes budget. It wraps ErrArgumentsLimit; the distinct sentinel
// identifies which limit tripped, so a caller can tell this budget apart from
// SecArgumentsLimit and decide whether the condition is fatal.
var ErrJSONDecodedSize = fmt.Errorf("json decoded size limit exceeded: %w", ErrArgumentsLimit)

// ErrJSONRecursionLimit is raised when a body nests deeper than the configured
// recursion limit. It does not wrap ErrArgumentsLimit: the parse fails and the
// entries collected so far are discarded, so it reports as a body error.
var ErrJSONRecursionLimit = errors.New("max recursion reached while reading json object")

// jsonDecodedBudget returns the decoded bytes a body of n bytes may produce.
// The slack it earns is proportional to it until it reaches the ceiling. The
// division tests for the product having overflowed, which a body larger than
// MaxInt/jsonDecodedBytesScale does on a 32-bit target: a wrapped product can
// land positive as easily as negative, and a small positive one would starve
// the budget rather than widen it.
func jsonDecodedBudget(n int) int {
	slack := n * jsonDecodedBytesScale
	if slack > jsonDecodedBytesSlack || slack/jsonDecodedBytesScale != n {
		slack = jsonDecodedBytesSlack
	}
	return n + slack
}

// lengthBudgetLeft reports whether another array-length entry fits the budget
// those entries share, which is the argument limit scaled by
// MaxEntriesPerArgument. A non-positive limit means unlimited.
func lengthBudgetLeft(maxArguments, lengths int) bool {
	return maxArguments <= 0 || lengths < scaleArgumentLimit(maxArguments, MaxEntriesPerArgument)
}

// jsonLimitError returns the limit an entry of n decoded bytes would breach,
// given the number of arguments already stored, or nil when the entry fits.
func jsonLimitError(n, maxArguments, args int, budget *int) error {
	if maxArguments > 0 && args >= maxArguments {
		return ErrArgumentsLimit
	}
	if n > *budget {
		return ErrJSONDecodedSize
	}
	return nil
}

func (js *jsonBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, bpo plugintypes.BodyProcessorOptions) error {
	// Read the entire body to store it and process it
	s := strings.Builder{}
	if _, err := io.Copy(&s, reader); err != nil {
		return err
	}
	ss := s.String()

	// Store the raw JSON in the TX variable for validateSchema before parsing,
	// so operators like @validateSchema keep their data even when parsing stops
	// early on the argument limit or the recursion-depth limit.
	// This is needed because ResponseBody is a Single interface without a Set method
	if txVar := v.TX(); txVar != nil && v.ResponseBody() != nil {
		txVar.Set("json_response_body", []string{ss})
	}

	col := v.ResponseArgs()
	// The recursion limit protects against deeply nested bodies exhausting the
	// stack; a non-positive value means unlimited.
	depth := bpo.RequestBodyRecursionLimit
	if depth <= 0 {
		depth = ignoreJSONRecursionLimit
	}
	data, err := readJSON(ss, depth, bpo.ArgumentLimit)
	if err != nil && !errors.Is(err, ErrArgumentsLimit) {
		return err
	}
	for key, value := range data {
		col.SetIndex(key, 0, value)
	}

	return err
}

func readJSON(s string, maxRecursion int, maxArguments int) (map[string]string, error) {
	res := make(map[string]string)
	key := []byte("json")

	if !gjson.Valid(s) {
		return res, errors.New("invalid JSON")
	}
	json := gjson.Parse(s)
	budget := jsonDecodedBudget(len(s))
	args := 0
	lengths := 0
	err := readItems(json, key, maxRecursion, maxArguments, &args, &lengths, &budget, res)
	return res, err
}

// Transform JSON to a map[string]string
// This function is recursive and will call itself for nested objects.
// Nesting is bounded by maxRecursion, the number of scalar values stored in
// res is counted in args and bounded by maxArguments (<= 0 means unlimited),
// and the total bytes stored (flattened keys plus values) are bounded by
// budget, which is decremented as entries are added. The array-length entry
// recorded for a non-empty array is not counted in args, because ModSecurity
// counts scalar values alone as arguments; those entries are counted in lengths
// and bounded by maxArguments scaled by MaxEntriesPerArgument, and exhausting
// that budget drops further lengths without stopping the parse. When
// maxArguments or budget is reached, parsing stops and ErrArgumentsLimit, or an
// error wrapping it, is returned with the entries collected so far; exceeding
// maxRecursion returns ErrJSONRecursionLimit instead.
// Example input: {"data": {"name": "John", "age": 30}, "items": [1,2,3]}
// Example output: map[string]string{"json.data.name": "John", "json.data.age": "30", "json.items.0": "1", "json.items.1": "2", "json.items.2": "3"}
// Example input: [{"data": {"name": "John", "age": 30}, "items": [1,2,3]}]
// Example output: map[string]string{"json.0.data.name": "John", "json.0.data.age": "30", "json.0.items.0": "1", "json.0.items.1": "2", "json.0.items.2": "3"}
func readItems(json gjson.Result, objKey []byte, maxRecursion int, maxArguments int, args *int, lengths *int, budget *int, res map[string]string) error {
	arrayLen := 0
	var iterationError error
	if maxRecursion == 0 {
		// We reached the limit of nesting we want to handle. This protects against
		// DoS attacks using deeply nested JSON structures (e.g., {"a":{"a":{"a":...}}}).
		return ErrJSONRecursionLimit
	}
	json.ForEach(func(key, value gjson.Result) bool {
		// Avoid string concatenation to maintain a single buffer for key aggregation.
		prevParentLength := len(objKey)
		objKey = append(objKey, '.')
		if key.Type == gjson.String {
			objKey = append(objKey, key.Str...)
		} else {
			objKey = strconv.AppendInt(objKey, int64(key.Num), 10)
			arrayLen++
		}

		var val string
		switch value.Type {
		case gjson.JSON:
			// call recursively with one less item to avoid doing infinite recursion
			iterationError = readItems(value, objKey, maxRecursion-1, maxArguments, args, lengths, budget, res)
			objKey = objKey[:prevParentLength]
			return iterationError == nil
		case gjson.String:
			val = value.Str
		case gjson.Null:
			val = ""
		default:
			// For all other types, raw JSON is what we need
			val = value.Raw
		}

		if err := jsonLimitError(len(objKey)+len(val), maxArguments, *args, budget); err != nil {
			iterationError = err
			objKey = objKey[:prevParentLength]
			return false
		}
		*budget -= len(objKey) + len(val)
		*args++
		res[string(objKey)] = val
		objKey = objKey[:prevParentLength]

		return true
	})
	// An iteration that stopped early never reached the remaining elements, so
	// arrayLen understates the array and no length is recorded for it.
	// Exhausting either budget drops the entry and lets the parse continue
	// rather than reporting a truncation. A document can hold more arrays than
	// it holds arguments, so failing here would deny bodies that carry no
	// arguments at all, and no portable rule can read what is dropped: neither
	// ModSecurity version records an array length, so a rule selecting one
	// would not load on the engines this corpus also targets. Dropping still
	// bounds what is stored, because an entry is only written while it fits.
	if arrayLen > 0 && iterationError == nil && lengthBudgetLeft(maxArguments, *lengths) {
		arrayLenVal := strconv.Itoa(arrayLen)
		if n := len(objKey) + len(arrayLenVal); n <= *budget {
			*budget -= n
			*lengths++
			res[string(objKey)] = arrayLenVal
		}
	}
	return iterationError
}

func init() {
	RegisterBodyProcessor("json", func() plugintypes.BodyProcessor {
		return &jsonBodyProcessor{}
	})
}
