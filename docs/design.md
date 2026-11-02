# Design

How doh looks, sounds, and behaves, so every screen feels like the same
product. It's a brief, not a rulebook: when a rule would make something
worse for the person using it, change the rule here first.

## Who it's for

- **A parent at the kitchen table** who wants the kids' tablets safe, a
  bedtime that holds, and to know nothing is wrong. Minutes, not manuals.
- **Someone who wants control** of their own network: what talks to what,
  and why, with nothing hidden.
- **The person who runs it for others**: a household, a school, a company,
  many tenants. Keyboard-fast, scriptable, precise.

They share one product. Simple things are on the surface; depth is one
click, one key, or one command away, never in the way.

## Identity: the ring

doh's mark is a donut, the project's own 🍩, read as a **ring** of
protection around a home. The ring is the logo, the shape of the Overview's
signature chart, and a small character.

- **The Overview ring** shows today's queries as a donut: the glaze is
  what went through, and each **sprinkle** is something that was blocked.
  Point at one to see what and why.
- **The character** is the ring with a face. It appears only where there's
  room for warmth: signing in, first run, empty states, a threat stopped,
  bedtime. It's calm when all is well and alert when something mattered.
  It never decorates dense screens, and never moves for someone who
  prefers reduced motion.

### The wordmark

"doh" is drawn, not typeset: round strokes for the d and the h, and the
donut itself for the o, glazed and sprinkled. The letters take the text
color, so the lockup works on any background; the donut keeps its glaze.
It's the `wordmark` symbol in the page's sprite, used in the sidebar and
the phone's top bar. Below about 20 px tall, use the mark alone.

## Color

Raspberry frosting on cool ink: warm and a little playful, serious enough
for administrators.

**One glaze, `#d6336c`,** wherever the brand appears: the mark and the
favicon, the wordmark's donut, the Overview ring, the setup progress
ring, primary actions, focus, switches that are on, and the current
place. It's the same in both themes, which it can be because it passes
4.5:1 with white text and 3:1 against both backgrounds. Two derivatives
do what it can't, and nothing else is pink:

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `--glaze` | `#d6336c` | `#d6336c` | the brand: the mark, actions, focus, the current place |
| `--glaze-ink` | `#b0245a` | `#ff8fb6` | pink text and links, which need 4.5:1 on every surface |
| `--glaze-soft` | `#fdebf2` | `#3a1527` | tints: the current place's background, selection, bars behind numbers |
| `--glaze-strong` | `#bd2a5f` | `#c42a60` | a primary action under the pointer |
| `--dough`, `--sprinkle` | | | the donut's base and sprinkles, nowhere else |
| `--text`, `--muted`, `--bg`, `--surface…` | | | cool neutrals |
| `--ok`, `--warn`, `--bad`, `--info` | | | status, each with a background |

`TestContrast` computes WCAG contrast from these tokens for every pair
the UI uses, in both themes, so a palette change can't quietly make doh
harder to read.

Status is never said by color alone: it always has words, and a symbol
(✓, ⚠, ⊘, ⓘ) where space is short. Both themes meet WCAG AA contrast for
text; `prefers-contrast: more` strengthens borders and muted text, and
forced colors (Windows High Contrast) use system colors throughout. People
can choose light, dark, or their system's, and the choice is remembered on
that device.

## Type, space, and shape

- System fonts, tuned rather than replaced (the page's policy loads no
  fonts): the platform's UI face for text, its rounded face for display
  where it has one (`ui-rounded`, SF Pro Rounded, Segoe UI Variable
  Display); tabular numbers wherever numbers line up or count.
- A fluid type scale (`--fs-xs` to `--fs-3xl`): sizes grow a little with
  the screen through `clamp()`, so headings are generous on a desktop
  without crowding a phone. Headings balance their lines; text avoids
  orphans.
- One spacing scale (`--s-1` to `--s-8`) and a fluid gutter, one radius
  scale, two shadows.
- Touch targets are at least 44 px on touch screens, and at least 24 px
  anywhere (`TestLayout` checks).

## Symbols

One set of stroke icons, drawn for doh on a 24-unit grid with a 1.75
stroke and round caps and joins, in the page's sprite. Nothing else is
an icon: no emoji, no text glyphs such as ✕ or →. Status uses words and
an icon together, never color alone.

## Texture

Grain, a fine noise from an inline SVG `feTurbulence` (a data URI: no
request, nothing the policy forbids), at 5% in light and 7% in dark,
like the matte of frosting. It's used where the brand speaks and nothing
needs reading closely: the sign-in screen and the setup guide's hero.
Never behind data, lists, or forms, where it would only be noise. High
contrast turns it off. Gradients follow the same rule: one soft glaze
halo on those same two surfaces, and none elsewhere.

## Motion

Tokens: `--t-fast` (120 ms), `--t` (200 ms), `--t-slow` (360 ms), and
`--t-moment` (640 ms); `--ease-out` for what arrives, `--ease-in` for what
leaves, and `--ease-spring`, a damped spring with one small overshoot
(CSS `linear()` where supported), for moments that deserve it.

- **Places** cross-fade and lift between URLs with the View Transitions
  API where the browser has it, and simply change where it doesn't.
- **Things that arrive** (a setup link, a live query, a notice) ease up
  into place; things that leave ease out, faster.
- **Moments**: a step done fills its segment of the setup ring; a device
  connecting turns "Waiting…" into the character, happy, with a burst of
  sprinkles. Nothing else celebrates.

Only opacity and transforms move, so nothing shifts the layout. For
someone who prefers reduced motion, none of it happens: states change
at once, and the waiting spinner stands still.

## Layout

- **Desktop**: a sidebar, content up to a comfortable width.
- **Tablet**: the sidebar folds to an icon rail.
- **Phone**: a bottom tab bar within thumb reach, respecting the safe area,
  with five places at most: Overview, Profiles, Activity, Explain,
  Settings. ⌘K reaches everything else. Nothing scrolls sideways.

Every view has a URL, so back, forward, reload, and links work; places
that moved keep their old URLs (`#/security` is Settings › Account).

**List, then detail.** Where something has sections, Settings and each
profile, they're a list of rows, each saying in a few words what it
holds. On a wide screen the chosen one sits beside the list; on a narrow
one it replaces the list, with a way back at the top. Which applies is
the space the component has (a container query), not the window's.
Never a strip of tabs that scrolls sideways.

**Many choices: a list to search, then one.** Where there are more than
a handful of options, such as the platforms to set a device up on,
they're a list grouped under small headings, with a search that matches
what people call things ("ps5", "chromebook") and says how many match.
Each row names the choice and its most important fact in a word and a
symbol (Encrypted, Plain DNS, Not available here); choosing one replaces
the list with its detail and a way back, and focus follows.

**Settings** has a home for everything that isn't the network itself:
You (account and passkeys, appearance), Household (people, alerts),
Automation (service accounts and the API), and Server (tenants, how the
server runs, and the change history of who changed what). New things go
in a group, not a new place in the tab bar: new alert destinations go
under Alerts, in its one list.

**Lists that grow** load a page at a time and the next as the end
scrolls into view, with a button for the same, so a year of changes
never renders at once. Every list has its loading, empty, and error
states, each saying what's happening in words.

## First run

A new server opens on the setup guide, not an empty Overview: add a
passkey, connect a first device, turn on alerts, point the router at
doh. Each step is worked out from what the server already knows and
checks itself off when it sees it done, so there's nothing to tick. The
guide stays on the Overview and in the sidebar until it's done or put
away, and in Settings after that.

Connecting a device ends in the product's one celebration: the setup
link's page waits, saying so, until the device asks its first question,
then says "Connected". The waiting status sits above the QR code, so on
a phone, where the code fills the screen, the moment happens in view;
if it's scrolled away, it's brought back, smoothly unless reduced
motion is preferred.

## Behavior

1. **Calm by default, clear when it matters.** Good news is quiet; things
   that need someone say so plainly, with what to do.
2. **Every number explains itself.** A count links to the queries behind
   it; an error says why and how to fix it.
3. **Undo over "are you sure?"** Reversible changes apply at once with an
   Undo. Irreversible ones, such as revoking a key, ask first and name the
   consequence on the button.
4. **Keyboard, mouse, and touch are equals.** ⌘K (Ctrl K) finds anything
   and does most things; `?` lists the shortcuts.
5. **Motion explains change**: what appeared, moved, or went away (see
   Motion). It never decorates, and it stops for reduced motion.
6. **Fast and owned.** No dependencies and no build step: plain modules,
   inline SVG icons drawn for doh, no web fonts, no requests to anyone
   else. A budget test holds the whole UI to 384 KiB as served (112 KiB
   compressed), and every module is preloaded, so pages don't wait on
   imports one level at a time.
7. **Empty is a moment, not a void.** An empty list says, with the
   character, what would be there and the one thing to do about it.

## Voice

Plain, warm, and specific. Say what happened, why, and what someone can do
about it, in that order. Prefer "Blocked: TikTok, during Homework (until
6 PM)" to "NXDOMAIN (policy)". Technical detail is welcome, one level down.
No exclamation marks for errors, no blame, no jargon on the surface.
