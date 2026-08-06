// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// ErrArgumentsLimit is returned by a body processor that could not store a
// body in full because one of its limits was reached. Members decoded before
// that point are kept. Most processors stop parsing there; multipart finishes
// the parse when only its part-header budget was exhausted. Processors may
// return an error wrapping this one to name the specific limit, so match it
// with errors.Is rather than by equality.
var ErrArgumentsLimit = errors.New("arguments limit exceeded")

// scaleArgumentLimit widens the argument limit into a budget larger than the
// number of arguments allowed, saturating instead of overflowing. The product
// wraps negative once limit exceeds MaxInt/factor, which a budget check reads
// as "nothing fits" where it guards on the unscaled limit and as "unlimited"
// where it guards on the scaled value, so processors sharing one configuration
// would disagree. MaxInt/factor is reachable on a 32-bit target for a limit the
// directive accepts, and on any target for a limit set through the Go API. A
// non-positive limit means unlimited and is returned unchanged.
func scaleArgumentLimit(limit, factor int) int {
	if limit <= 0 {
		return limit
	}
	if limit > math.MaxInt/factor {
		return math.MaxInt
	}
	return limit * factor
}

type bodyProcessorWrapper = func() plugintypes.BodyProcessor

var processors = map[string]bodyProcessorWrapper{}

// RegisterBodyProcessor registers a body processor
// by name. If the body processor is already registered,
// it will be overwritten
func RegisterBodyProcessor(name string, fn func() plugintypes.BodyProcessor) {
	processors[name] = fn
}

// GetBodyProcessor returns a body processor by name
// If the body processor is not found, it returns an error
func GetBodyProcessor(name string) (plugintypes.BodyProcessor, error) {
	if fn, ok := processors[strings.ToLower(name)]; ok {
		return fn(), nil
	}
	return nil, fmt.Errorf("invalid bodyprocessor %q", name)
}
