/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "johncommandbuilder.h"

namespace forensic {

namespace {

JohnBuildResult unsupported(const QString &why)
{
    JohnBuildResult r;
    r.supported = false;
    r.error = why;
    return r;
}

bool hasCustomCharsets(const AttackJobSpec &spec)
{
    return !spec.customCharset1.isEmpty() || !spec.customCharset2.isEmpty()
           || !spec.customCharset3.isEmpty() || !spec.customCharset4.isEmpty();
}

} // namespace

JohnBuildResult JohnCommandBuilder::build(const AttackJobSpec &spec)
{
    // ---- Features John cannot express from a hashcat-shaped spec ----
    // These are refused up front, before we look at the attack mode, so the
    // examiner gets one clear reason instead of a subtly wrong run.

    if (!spec.rules.isEmpty())
        return unsupported(QStringLiteral(
            "Rule files are hashcat mangling rules; John uses its own named rule "
            "sets and cannot run these rule files. Use hashcat for this attack."));

    if (hasCustomCharsets(spec))
        return unsupported(QStringLiteral(
            "Custom charsets (-1..-4) are hashcat mask placeholders; John's mask "
            "mode does not accept them here. Use hashcat for this attack."));

    if (!spec.extraArgs.isEmpty())
        return unsupported(QStringLiteral(
            "This attack carries raw hashcat arguments that cannot be forwarded "
            "to John. Use hashcat for this attack."));

    switch (spec.attackMode) {
    case AttackModeNum::Combination:
        return unsupported(QStringLiteral(
            "Combinator attacks (two wordlists joined) are not expressible by "
            "John. Use hashcat for this attack."));
    case AttackModeNum::HybridWordMask:
    case AttackModeNum::HybridMaskWord:
        return unsupported(QStringLiteral(
            "Hybrid wordlist+mask attacks are not expressible by John. Use "
            "hashcat for this attack."));
    default:
        break;
    }

    // ---- Attacks John expresses cleanly ----
    JohnBuildResult r;
    QStringList args;

    switch (spec.attackMode) {
    case AttackModeNum::Straight: {
        // Dictionary attack. John's --wordlist takes exactly one file; hashcat
        // can chain several. Refuse rather than silently run only the first.
        if (spec.wordlists.size() != 1)
            return unsupported(QStringLiteral(
                "John runs a single wordlist per attack (this attack has %1). "
                "Split it into separate John attacks, or use hashcat.")
                                   .arg(spec.wordlists.size()));
        args << (QStringLiteral("--wordlist=") + spec.wordlists.first());
        break;
    }
    case AttackModeNum::BruteForceMask: {
        const bool hasMask = !spec.mask.isEmpty();
        if (hasMask) {
            // Mask attack. --increment maps to John's variable mask length:
            // testing the mask truncated to lengths [min,max] is exactly what
            // John's --min-length/--max-length do over a mask.
            args << (QStringLiteral("--mask=") + spec.mask);
            if (spec.increment) {
                if (spec.incrementMin > 0)
                    args << (QStringLiteral("--min-length=") + QString::number(spec.incrementMin));
                if (spec.incrementMax > 0)
                    args << (QStringLiteral("--max-length=") + QString::number(spec.incrementMax));
            }
        } else if (spec.increment) {
            // Brute force with no explicit mask is John's incremental mode.
            args << QStringLiteral("--incremental");
        } else {
            return unsupported(QStringLiteral(
                "A brute-force attack needs either a mask or incremental mode; "
                "this attack specifies neither."));
        }
        break;
    }
    default:
        return unsupported(QStringLiteral(
            "Attack mode %1 is not expressible by John. Use hashcat for this "
            "attack.")
                               .arg(spec.attackMode));
    }

    // John auto-detects the hash format from the *2john output's own tag (e.g.
    // $office$, $bitlocker$), so no explicit --format is needed or guessed. The
    // hash file is the trailing positional argument.
    if (!spec.hashFile.isEmpty())
        args << spec.hashFile;

    r.supported = true;
    r.args = args;
    return r;
}

} // namespace forensic
