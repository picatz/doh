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

## Color

Raspberry frosting on cool ink: warm and a little playful, serious enough
for administrators.

| Token | Use |
| --- | --- |
| `--glaze` | the accent: primary actions, the current place, focus |
| `--ink`, `--paper` | text and background, cool neutrals |
| `--ok`, `--warn`, `--bad`, `--info` | status |

Status is never said by color alone: it always has words, and a symbol
(✓, ⚠, ⊘, ⓘ) where space is short. Both themes meet WCAG AA contrast for
text; `prefers-contrast: more` strengthens borders and muted text, and
forced colors (Windows High Contrast) use system colors throughout. People
can choose light, dark, or their system's, and the choice is remembered on
that device.

## Type, space, and shape

- System fonts, with rounded faces for display where the platform has them
  (`ui-rounded`); tabular numbers wherever numbers line up.
- One spacing scale (`--s-1` to `--s-8`), one radius scale, two shadows.
- Touch targets are at least 44 px on touch screens.

## Layout

- **Desktop**: a sidebar, content up to a comfortable width.
- **Tablet**: the sidebar folds to an icon rail.
- **Phone**: a bottom tab bar within thumb reach, respecting the safe area;
  nothing scrolls sideways.

Every view has a URL, so back, forward, reload, and links work.

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
5. **Motion explains change**: what appeared, moved, or went away, in
   150–250 ms. It never decorates, and it stops for reduced motion.
6. **Fast and owned.** No dependencies and no build step: plain modules,
   inline SVG icons drawn for doh, no web fonts, no requests to anyone else.

## Voice

Plain, warm, and specific. Say what happened, why, and what someone can do
about it, in that order. Prefer "Blocked: TikTok, during Homework (until
6 PM)" to "NXDOMAIN (policy)". Technical detail is welcome, one level down.
No exclamation marks for errors, no blame, no jargon on the surface.
