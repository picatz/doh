// Tests for static/schedule.js, run by TestScheduleModule with node --test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { scheduleActive, formatDays, formatPeriod, describeBlocks, clockMinutes, overnight } from "../static/schedule.js";

// at returns the instant of a wall-clock time in a time zone, for dates in
// November 2026, when New York is at UTC-5: 2026-11-02 is a Monday.
const at = (date, hhmm, offset = "-05:00") => new Date(`2026-11-${date}T${hhmm}:00${offset}`);
const NY = "America/New_York";

const homework = { days: ["mon", "tue", "wed", "thu", "fri"], start: "15:00", end: "18:00" };
const bedtime = { days: ["sun", "mon", "tue", "wed", "thu"], start: "21:00", end: "07:00" };

test("scheduleActive within a day", () => {
  assert.equal(scheduleActive(homework, at("02", "16:30"), NY), true);
  assert.equal(scheduleActive(homework, at("02", "15:00"), NY), true, "starts on the minute");
  assert.equal(scheduleActive(homework, at("02", "18:00"), NY), false, "ends on the minute");
  assert.equal(scheduleActive(homework, at("07", "16:00"), NY), false, "Saturday");
});

test("scheduleActive past midnight belongs to its start day", () => {
  assert.equal(scheduleActive(bedtime, at("01", "22:00"), NY), true, "Sunday night");
  assert.equal(scheduleActive(bedtime, at("02", "06:59"), NY), true, "Monday morning, from Sunday");
  assert.equal(scheduleActive(bedtime, at("02", "07:00"), NY), false);
  assert.equal(scheduleActive(bedtime, at("06", "22:00"), NY), false, "Friday night");
  assert.equal(scheduleActive(bedtime, at("06", "06:00"), NY), true, "Friday morning, from Thursday");
  assert.equal(scheduleActive(bedtime, at("01", "06:00"), NY), false, "Sunday morning, from Saturday");
});

test("scheduleActive uses the profile's time zone, not the browser's", () => {
  // 03:00 UTC Monday is 22:00 Sunday in New York: bedtime there.
  const instant = new Date("2026-11-02T03:00:00Z");
  assert.equal(scheduleActive(bedtime, instant, NY), true);
  // In Tokyo it's 12:00 Monday.
  assert.equal(scheduleActive(bedtime, instant, "Asia/Tokyo"), false);
  assert.equal(scheduleActive({ start: "11:00", end: "13:00" }, instant, "Asia/Tokyo"), true, "no days is every day");
});

test("scheduleActive is unknown without a usable time zone or clock", () => {
  assert.equal(scheduleActive(bedtime, new Date(), ""), null);
  assert.equal(scheduleActive(bedtime, new Date(), "Mars/Olympus_Mons"), null);
  assert.equal(scheduleActive({ start: "25:00", end: "07:00" }, new Date(), NY), null);
});

test("formatDays", () => {
  for (const [days, want] of [
    [undefined, "Every day"],
    [[], "Every day"],
    [["sun", "mon", "tue", "wed", "thu", "fri", "sat"], "Every day"],
    [["mon", "tue", "wed", "thu", "fri"], "Mon–Fri"],
    [["sun", "mon", "tue", "wed", "thu"], "Sun–Thu"],
    [["sat", "sun"], "Sat, Sun"],
    [["fri", "sat", "sun", "mon"], "Fri–Mon"],
    [["mon", "tue", "wed", "fri"], "Mon–Wed, Fri"],
    [["tue"], "Tue"],
  ]) {
    assert.equal(formatDays(days), want, JSON.stringify(days));
  }
});

test("describeBlocks", () => {
  const names = (kind, id) => (kind === "service" ? { youtube: "YouTube" }[id] : `${id} list`) || id;
  assert.equal(describeBlocks({ block_all: true }), "everything");
  assert.equal(describeBlocks({ block_all: true, allow: ["school.example"] }), "everything except school.example");
  assert.equal(describeBlocks({ services: ["youtube"], lists: ["social"], deny: ["games.example"] }, names), "YouTube, social list, games.example");
  assert.equal(describeBlocks({}), "nothing");
});

test("clocks", () => {
  assert.equal(clockMinutes("07:30"), 450);
  assert.ok(Number.isNaN(clockMinutes("7:30")));
  assert.ok(Number.isNaN(clockMinutes("24:00")));
  assert.equal(overnight(bedtime), true);
  assert.equal(overnight(homework), false);
});

test("scheduleActive all day, when it ends when it starts", () => {
  const weekend = { name: "Weekend", days: ["sat", "sun"], start: "00:00", end: "00:00", services: ["youtube"] };
  assert.equal(scheduleActive(weekend, at("07", "00:00"), NY), true);
  assert.equal(scheduleActive(weekend, at("08", "23:59"), NY), true);
  assert.equal(scheduleActive(weekend, at("09", "00:00"), NY), false);
  assert.equal(formatPeriod(weekend), "all day");
  assert.equal(formatPeriod({ start: "21:00", end: "07:00" }), "21:00–07:00");
});
