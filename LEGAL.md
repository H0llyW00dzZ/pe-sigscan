# Legal Notice for pe-sigscan

`pe-sigscan` is a byte-pattern matching primitive. The same operation
backs antivirus engines, EDR products, performance profilers, kernel
debuggers (WinDbg, x64dbg), malware-analysis sandboxes, and
reverse-engineering toolkits (IDA, Ghidra, Binary Ninja, Frida). The
crate ships no exploits, no copyright-circumvention logic, and no
memory-write or code-injection helpers — it reads bytes you can already
read in your own process and reports where a pattern matches.

## Legitimate use

The categories listed under [Use Cases](#use-cases) in the README —
game modding, in-process tooling, reverse engineering, malware analysis,
security research, and debugging — are well-established forms of software
engineering and research with explicit legal grounding:

- **United States.** Reverse engineering for interoperability,
  compatibility analysis, and security research is established case law
  (*Sega Enterprises Ltd. v. Accolade, Inc.*, 977 F.2d 1510 (9th Cir.
  1992); *Sony Computer Entertainment v. Connectix Corp.*, 203 F.3d 596
  (9th Cir. 2000)). 17 U.S.C. § 117 permits the owner of a software
  copy to make adaptations needed to use it. DMCA § 1201(f) explicitly
  permits reverse engineering of computer programs for interoperability.
  Modding, debugging, and analysis workflows that don't reproduce or
  redistribute the underlying program generally fall well inside these
  protections.
- **European Union.** Directive 2009/24/EC Article 6 codifies a
  near-identical reverse-engineering-for-interoperability right; Article
  5(3) permits observation, study, and testing of program function.
- **Other jurisdictions.** Laws vary. Germany's § 202c StGB
  ("Hackerparagraph"), South Korea's Game Industry Promotion Act
  (which criminalises certain anti-cheat circumvention), and analogous
  statutes elsewhere may apply more restrictively to specific
  categories — notably online-game cheating, unauthorized access to
  computer systems, or circumvention of technological protection
  measures. Check your local statute if your use case touches those
  areas.

## Responsibility

What you do with the matched addresses is on you, not on the tool.
Reading the memory of a process you own and run is generally lawful in
the jurisdictions above. Using the results to:

- **Modify a single-player game, hot-patch your own software, or
  fingerprint code for a debugger or analysis tool** — typically
  lawful.
- **Cheat in an online multiplayer game** — usually breaches the
  game's Terms of Service. This is generally a civil/contract matter
  (account bans, possible civil suits — see e.g. *Bungie, Inc. v.
  AimJunkies.com et al.*, W.D. Wash.), not a criminal one in most
  Western jurisdictions, but the answer differs in others.
- **Bypass a Technological Protection Measure on copyrighted
  content** — may engage DMCA § 1201, EU Copyright Directive Article
  6, or equivalent foreign provisions, depending on what specifically
  is bypassed.
- **Access a system you don't own or aren't authorised to use** —
  likely violates the U.S. Computer Fraud and Abuse Act (18 U.S.C.
  § 1030) or an equivalent foreign statute, regardless of what tool
  you used.

## Disclaimer

This section is a high-level summary intended to help you decide
whether to investigate your specific situation further. It is **not
legal advice.** If your intended use sits anywhere near a grey area,
consult a qualified attorney in your jurisdiction.

The project is published and maintained as a general-purpose software
engineering library. The maintainers don't endorse, condone, or
provide support for use against systems the user doesn't own, or
against the published Terms of Service of any product. Issue reports
and pull requests focused on such use will be closed without comment.
