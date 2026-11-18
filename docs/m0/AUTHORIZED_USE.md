# Authorized use

This code is a red-team C2 framework component built for an **authorized**
engagement. It must only be used on systems for which the operator holds written
authorization from the asset owner, and within the scope, time window and rules
of engagement recorded for that engagement.

## Rules

1. **Scope first.** Confirm the target host/subnet appears in the engagement
   authorization before connecting a client or running a task against it.
2. **Least impact.** Prefer read-only tasks (`sysinfo`, `ping`). `exec` remains
   disabled unless the rules of engagement explicitly authorize command
   execution, and even then only for the approved actions.
3. **No third-party systems.** Do not pivot into systems outside the authorized
   scope, even if reachable from a target.
4. **Data handling.** Any data retrieved is engagement-confidential: store it in
   the designated engagement directory, never in this repository, and delete it
   per the engagement's retention rules.
5. **Honest reporting.** Report what was actually observed, with command output
   or logs as evidence. Never claim a build, test or access that did not happen.
6. **Stop conditions.** Stop immediately if a task risks availability (service
   restart, disk fill, lockout) unless the engagement authorizes it.

## Defaults that enforce this

* Everything binds to loopback by default (`127.0.0.1:9909`, `127.0.0.1:9910`).
* `c2builder` refuses callback hosts outside `example.com`, `*.example.com`,
  `203.0.113.0/24` and loopback unless `--allow-any-host` is passed.
* The client refuses `exec` without `--allow-exec`.
* The server refuses to start without an operator PSK unless explicitly
  overridden.

## Out of scope by default

Public internet hosts, third-party SaaS, the operator's own workstation, and any
system not named in the engagement authorization. Icons, filenames and
persistence mechanisms that impersonate the target's software are out of scope
until M2 and require explicit approval.
