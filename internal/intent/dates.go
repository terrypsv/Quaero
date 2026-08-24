// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

import "time"

// now is swappable in tests so that a query built today and a query built in
// six months can be compared against a fixed expectation.
var now = time.Now

func daysAgo(days int) string {
	return now().AddDate(0, 0, -days).Format("2006-01-02")
}
