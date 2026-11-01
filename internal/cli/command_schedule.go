package cli

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/picatz/doh/internal/client"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/services"
	"github.com/spf13/cobra"
)

// dayNames are the short day names people read, by time.Weekday.
var dayNames = [7]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

// dayAliases name common sets of days, as "doh schedule add --days" takes
// them.
var dayAliases = map[string][]string{
	"weekdays":      {"mon", "tue", "wed", "thu", "fri"},
	"weekends":      {"sat", "sun"},
	"school-nights": {"sun", "mon", "tue", "wed", "thu"},
}

// parseDays parses a --days value: day names (sun, monday), ranges
// (mon-fri, fri-sun), and aliases (weekdays, weekends, school-nights,
// every-day), comma separated, into days in week order. Every day is the
// empty list, as schedules store it.
func parseDays(s string) ([]string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "every day", "every-day", "everyday", "daily", "all":
		return nil, nil
	}

	var set [7]bool
	for part := range strings.SplitSeq(s, ",") {
		part = strings.ReplaceAll(strings.TrimSpace(part), " ", "-")
		if days, ok := dayAliases[part]; ok {
			for _, d := range days {
				set[slices.Index(policy.Weekdays[:], d)] = true
			}
			continue
		}
		from, to, isRange := strings.Cut(part, "-")
		start, err := weekday(from)
		if err != nil {
			return nil, err
		}
		end := start
		if isRange {
			if end, err = weekday(to); err != nil {
				return nil, err
			}
		}
		// Ranges may wrap around the week, as fri-mon does.
		for d := start; ; d = (d + 1) % 7 {
			set[d] = true
			if d == end {
				break
			}
		}
	}

	var days []string
	for i, on := range set {
		if on {
			days = append(days, policy.Weekdays[i])
		}
	}
	if len(days) == 7 {
		return nil, nil
	}
	return days, nil
}

// weekday parses a day name, short or long, such as "mon" or "Monday".
func weekday(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) >= 3 {
		if i := slices.Index(policy.Weekdays[:], s[:3]); i >= 0 && strings.HasPrefix(strings.ToLower(time.Weekday(i).String()), s) {
			return i, nil
		}
	}
	return 0, fmt.Errorf("unknown day %q: use names such as mon or monday, ranges such as mon-fri, or weekdays, weekends, school-nights, or every-day", s)
}

// formatDays describes days compactly, as "Every day", "Mon–Fri", or
// "Sat, Sun": runs of consecutive days, wrapping around the week.
func formatDays(days []string) string {
	var set [7]bool
	for _, d := range days {
		if i := slices.Index(policy.Weekdays[:], d); i >= 0 {
			set[i] = true
		}
	}
	n := 0
	for _, on := range set {
		if on {
			n++
		}
	}
	if n == 0 || n == 7 {
		return "Every day"
	}

	// Start at a day that begins a run, so runs that wrap past Saturday
	// stay whole.
	first := 0
	for i := range 7 {
		if set[i] && !set[(i+6)%7] {
			first = i
			break
		}
	}

	var runs []string
	for k := 0; k < 7; {
		i := (first + k) % 7
		if !set[i] {
			k++
			continue
		}
		length := 0
		for length+k < 7 && set[(i+length)%7] {
			length++
		}
		switch end := (i + length - 1) % 7; length {
		case 1:
			runs = append(runs, dayNames[i])
		case 2:
			runs = append(runs, dayNames[i], dayNames[end])
		default:
			runs = append(runs, dayNames[i]+"–"+dayNames[end])
		}
		k += length
	}
	return strings.Join(runs, ", ")
}

// describeBlocks says what a schedule blocks, for people.
func describeBlocks(sc policy.Schedule) string {
	if sc.BlockAll {
		if len(sc.Allow) == 0 {
			return "everything"
		}
		return "everything but " + strings.Join(sc.Allow, ", ")
	}
	parts := serviceNames(sc.Services)
	parts = append(parts, sc.Lists...)
	parts = append(parts, sc.Deny...)
	return strings.Join(parts, ", ")
}

// serviceNames returns the names of the services with ids, keeping the IDs
// of any it doesn't know.
func serviceNames(ids []string) []string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		if s, ok := services.Lookup(id); ok {
			id = s.Name
		}
		names = append(names, id)
	}
	return names
}

// scheduleActive reports whether sc is in effect at now, in the profile's
// time zone, as the server decides it: a period that ends before it starts
// runs past midnight and belongs to the day it started on, and one that
// ends when it starts lasts all day.
func scheduleActive(sc policy.Schedule, now time.Time) bool {
	start, err1 := policy.ParseClock(sc.Start)
	end, err2 := policy.ParseClock(sc.End)
	if err1 != nil || err2 != nil {
		return false
	}
	on := func(d time.Weekday) bool {
		return len(sc.Days) == 0 || slices.Contains(sc.Days, policy.Weekdays[d])
	}
	minute := now.Hour()*60 + now.Minute()
	today := now.Weekday()
	switch {
	case start == end:
		return on(today)
	case start < end:
		return on(today) && start <= minute && minute < end
	}
	return (on(today) && minute >= start) || (on((today+6)%7) && minute < end)
}

// profileNow returns the current time in p's time zone, and whether it's
// known: without a time zone, schedules follow the server's, which may
// differ from this machine's.
func profileNow(p *policy.Profile, now time.Time) (time.Time, bool) {
	if p.TimeZone == "" {
		return now, false
	}
	loc, err := time.LoadLocation(p.TimeZone)
	if err != nil {
		return now, false
	}
	return now.In(loc), true
}

// printSchedules writes p's schedules as a table.
func printSchedules(w io.Writer, p *policy.Profile, now time.Time) error {
	if len(p.Schedules) == 0 {
		fmt.Fprintf(w, "Profile %q has no schedules. Add one with: doh schedule add %s --name Bedtime --days school-nights --start 21:00 --end 07:00 --block-all\n", p.ID, p.ID)
		return nil
	}

	local, known := profileNow(p, now)
	tw := newTable(w)
	fmt.Fprintln(tw, "NAME\tDAYS\tTIME\tBLOCKS\tNOW")
	for _, sc := range p.Schedules {
		state := "-"
		switch {
		case !known:
			state = "?"
		case scheduleActive(sc, local):
			state = "active"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", sc.Name, formatDays(sc.Days), formatPeriod(sc), describeBlocks(sc), state)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if !known {
		fmt.Fprintf(w, "\nSchedules follow the server's time zone. Set the profile's with: doh profile set %s time_zone=America/New_York\n", p.ID)
	}
	return nil
}

// updateSchedules changes a profile's schedules with change, as a merge
// patch made only if the policy hasn't changed since it was read, trying
// once more if it had.
func updateSchedules(ctx context.Context, c *client.Client, id string, change func([]policy.Schedule) ([]policy.Schedule, error)) (*policy.Profile, error) {
	for attempt := 0; ; attempt++ {
		p, etag, err := c.ProfileVersion(ctx, id)
		if err != nil {
			return nil, err
		}
		next, err := change(slices.Clone(p.Schedules))
		if err != nil {
			return nil, err
		}
		// A merge patch replaces arrays whole; an empty one removes them.
		var value any = next
		if len(next) == 0 {
			value = nil
		}
		updated, err := c.PatchProfileIf(ctx, id, map[string]any{"schedules": value}, etag)
		if client.IsPreconditionFailed(err) && attempt == 0 {
			continue // someone else changed the policy: reread and retry
		}
		return updated, err
	}
}

// newScheduleCommand returns "doh schedule" and its subcommands.
func newScheduleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "List, add, and remove a profile's schedules",
		Long: `List, add, and remove the schedules of a profile on a running doh server.

A schedule blocks more during a recurring period, such as social apps during
homework, or everything but school sites at bedtime. Periods that end before
they start run past midnight and belong to the day they start on, so a
school-nights bedtime from 21:00 to 07:00 lasts into each school morning.

Schedules follow the profile's time zone, set with
"doh profile set <profile> time_zone=America/New_York", or the server's.`,
	}

	list := &cobra.Command{
		Use:          "list <profile>",
		Short:        "List a profile's schedules",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	listFlags := addClientFlags(list)
	list.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := listFlags.client()
		if err != nil {
			return err
		}
		p, err := c.Profile(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		if listFlags.json {
			return printJSON(cmd.OutOrStdout(), cmpSlice(p.Schedules))
		}
		return printSchedules(cmd.OutOrStdout(), p, time.Now())
	}

	var (
		sc       policy.Schedule
		daysFlag string
	)
	add := &cobra.Command{
		Use:   "add <profile> --name NAME --start HH:MM --end HH:MM [flags]",
		Short: "Add a schedule to a profile",
		Long: `Add a schedule to a profile: what to block, on which days, and when.

Days are names (sun, monday), ranges (mon-fri), or weekdays, weekends,
school-nights (sun-thu), or every-day, comma separated. With --block-all,
everything but --allow domains, the profile's allowed domains, and local
names such as the router is blocked; otherwise, the --service apps, --list
blocklists, and --deny domains are.

Examples:
  doh schedule add kids --name Homework --days weekdays --start 15:00 --end 18:00 --service youtube --service roblox
  doh schedule add kids --name Bedtime --days school-nights --start 21:00 --end 07:00 --block-all --allow school.example
  doh schedule add kids --name Weekend --days sat,sun --start 08:00 --end 10:00 --list social`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	addFlags := addClientFlags(add)
	af := add.Flags()
	af.StringVar(&sc.Name, "name", "", "what to call it, such as Bedtime (required)")
	af.StringVar(&daysFlag, "days", "every-day", "days it starts on")
	af.StringVar(&sc.Start, "start", "", "when it starts, as HH:MM (required)")
	af.StringVar(&sc.End, "end", "", "when it ends, as HH:MM; before --start runs past midnight (required)")
	af.BoolVar(&sc.BlockAll, "block-all", false, "block everything but --allow domains and local names")
	af.StringArrayVar(&sc.Allow, "allow", nil, "a domain --block-all lets through (repeatable)")
	af.StringArrayVar(&sc.Services, "service", nil, "an app to block, from doh services (repeatable)")
	af.StringArrayVar(&sc.Lists, "list", nil, "a blocklist to apply, from doh blocklist presets (repeatable)")
	af.StringArrayVar(&sc.Deny, "deny", nil, "a domain to block (repeatable)")
	add.RunE = func(cmd *cobra.Command, args []string) error {
		days, err := parseDays(daysFlag)
		if err != nil {
			return err
		}
		sc.Days = days
		if err := checkSchedule(sc); err != nil {
			return err
		}

		c, err := addFlags.client()
		if err != nil {
			return err
		}
		p, err := updateSchedules(cmd.Context(), c, args[0], func(existing []policy.Schedule) ([]policy.Schedule, error) {
			if slices.ContainsFunc(existing, func(e policy.Schedule) bool { return strings.EqualFold(e.Name, sc.Name) }) {
				return nil, fmt.Errorf("profile %q already has a schedule named %q; remove it first, or choose another name", args[0], sc.Name)
			}
			return append(existing, sc), nil
		})
		if err != nil {
			return err
		}
		if addFlags.json {
			return printJSON(cmd.OutOrStdout(), p.Schedules)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Added %q to profile %q: %s %s, blocking %s.\n", sc.Name, p.ID, formatDays(sc.Days), formatPeriod(sc), describeBlocks(sc))
		if mustClock(sc.End) < mustClock(sc.Start) {
			fmt.Fprintln(cmd.OutOrStdout(), "It runs past midnight into the next morning.")
		}
		return nil
	}

	remove := &cobra.Command{
		Use:          "remove <profile> <name>",
		Short:        "Remove a schedule from a profile",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
	}
	removeFlags := addClientFlags(remove)
	remove.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := removeFlags.client()
		if err != nil {
			return err
		}
		removed := args[1]
		_, err = updateSchedules(cmd.Context(), c, args[0], func(existing []policy.Schedule) ([]policy.Schedule, error) {
			i := slices.IndexFunc(existing, func(e policy.Schedule) bool { return strings.EqualFold(e.Name, args[1]) })
			if i < 0 {
				names := make([]string, len(existing))
				for j, e := range existing {
					names[j] = e.Name
				}
				if len(names) == 0 {
					return nil, fmt.Errorf("profile %q has no schedules", args[0])
				}
				return nil, fmt.Errorf("profile %q has no schedule named %q (it has %s)", args[0], args[1], strings.Join(names, ", "))
			}
			removed = existing[i].Name
			return slices.Delete(existing, i, i+1), nil
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Removed %q from profile %q.\n", removed, args[0])
		return nil
	}

	cmd.AddCommand(list, add, remove)
	return cmd
}

// checkSchedule reports problems with sc that the server would refuse, in
// friendlier terms, before anything is sent.
func checkSchedule(sc policy.Schedule) error {
	if n := strings.TrimSpace(sc.Name); n == "" || len(n) > 64 {
		return fmt.Errorf("name the schedule with --name, such as --name Bedtime")
	}
	if _, err := policy.ParseClock(sc.Start); err != nil {
		return fmt.Errorf("--start: %w", err)
	}
	if _, err := policy.ParseClock(sc.End); err != nil {
		return fmt.Errorf("--end: %w", err)
	}
	if !sc.BlockAll && len(sc.Services) == 0 && len(sc.Lists) == 0 && len(sc.Deny) == 0 {
		return fmt.Errorf("say what to block: --block-all, or --service, --list, or --deny")
	}
	if !sc.BlockAll && len(sc.Allow) > 0 {
		return fmt.Errorf("--allow only applies with --block-all")
	}
	for _, id := range sc.Services {
		if _, ok := services.Lookup(id); !ok {
			return fmt.Errorf("unknown service %q (see doh services)", id)
		}
	}
	return nil
}

// mustClock parses a time already checked by checkSchedule.
func mustClock(s string) int {
	m, _ := policy.ParseClock(s)
	return m
}

// cmpSlice returns s, or an empty slice for nil, so JSON says [] rather
// than null.
func cmpSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// newServicesCommand returns "doh services".
func newServicesCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "services",
		Short: "List the apps and sites profiles can block by name",
		Long: `List the apps and sites profiles and schedules can block by name.

Block one always with "doh profile set <profile> services=tiktok,roblox", or
during a schedule with "doh schedule add --service".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if asJSON {
				return printJSON(cmd.OutOrStdout(), services.Catalog)
			}
			tw := newTable(cmd.OutOrStdout())
			fmt.Fprintln(tw, "ID\tNAME\tCATEGORY\tDOMAINS")
			for _, s := range services.Catalog {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", s.ID, s.Name, s.Category, len(s.Domains))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON instead of text")
	return cmd
}

// formatPeriod describes a schedule's times, as "21:00–07:00", or "all
// day" when it ends when it starts.
func formatPeriod(sc policy.Schedule) string {
	if sc.Start == sc.End {
		return "all day"
	}
	return sc.Start + "–" + sc.End
}
