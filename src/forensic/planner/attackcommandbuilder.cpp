/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "attackcommandbuilder.h"

namespace forensic {

QStringList AttackCommandBuilder::buildArgs(const AttackJobSpec &spec)
{
    QStringList args;
    args << QStringLiteral("-m") << QString::number(spec.hashMode);
    args << QStringLiteral("-a") << QString::number(spec.attackMode);

    if (spec.optimizedKernel)
        args << QStringLiteral("-O");

    // Custom charsets (used by mask/hybrid attacks).
    if (!spec.customCharset1.isEmpty()) args << QStringLiteral("-1") << spec.customCharset1;
    if (!spec.customCharset2.isEmpty()) args << QStringLiteral("-2") << spec.customCharset2;
    if (!spec.customCharset3.isEmpty()) args << QStringLiteral("-3") << spec.customCharset3;
    if (!spec.customCharset4.isEmpty()) args << QStringLiteral("-4") << spec.customCharset4;

    if (spec.increment) {
        args << QStringLiteral("--increment");
        if (spec.incrementMin > 0)
            args << QStringLiteral("--increment-min") << QString::number(spec.incrementMin);
        if (spec.incrementMax > 0)
            args << QStringLiteral("--increment-max") << QString::number(spec.incrementMax);
    }

    for (const QString &rule : spec.rules)
        args << QStringLiteral("-r") << rule;

    // The hash file is the first positional argument for every attack mode.
    if (!spec.hashFile.isEmpty())
        args << spec.hashFile;

    // Positional inputs after the hash file depend on the attack mode.
    switch (spec.attackMode) {
    case AttackModeNum::Straight:
    case AttackModeNum::Combination:
        args << spec.wordlists;
        break;
    case AttackModeNum::BruteForceMask:
        if (!spec.mask.isEmpty())
            args << spec.mask;
        break;
    case AttackModeNum::HybridWordMask: // wordlist then mask
        args << spec.wordlists;
        if (!spec.mask.isEmpty())
            args << spec.mask;
        break;
    case AttackModeNum::HybridMaskWord: // mask then wordlist
        if (!spec.mask.isEmpty())
            args << spec.mask;
        args << spec.wordlists;
        break;
    default:
        args << spec.wordlists;
        if (!spec.mask.isEmpty())
            args << spec.mask;
        break;
    }

    args << spec.extraArgs;
    return args;
}

QStringList AttackCommandBuilder::buildCommand(const AttackJobSpec &spec, const QString &program)
{
    QStringList cmd;
    cmd << program;
    cmd << buildArgs(spec);
    return cmd;
}

} // namespace forensic
