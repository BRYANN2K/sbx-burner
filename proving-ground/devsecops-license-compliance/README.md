# devsecops-license-compliance

Thumbnail service (`project/`) with a real `npm install --package-lock-only`
lockfile. Nothing is installed or vendored: the target is lockfile-only, and
licences are what `package-lock.json` records.

| package | licence (lockfile) | shipped | expected |
| --- | --- | --- | --- |
| ffmpeg-static 5.2.0 | GPL-3.0-or-later | yes | finding (deny) |
| parse-cache-control 1.0.1 | none | yes (transitive) | hypothesis (unknown -> review) |
| mupdf 1.28.6 | AGPL-3.0-or-later | no (devDependency) | not a finding (lead at most) |

parse-cache-control's registry metadata carries a legacy
`licenses: [{type: BSD}]` field, but its lockfile entry has no `license`.
The proving ground scores the lockfile view: a run that looks the package up
on the registry may still call it unknown, and must not upgrade it to a
finding.
