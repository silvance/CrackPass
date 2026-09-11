/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "attackjobspec.h"

namespace forensic {

QString attackModeName(int attackMode)
{
    switch (attackMode) {
    case AttackModeNum::Straight:       return QStringLiteral("Straight (dictionary)");
    case AttackModeNum::Combination:    return QStringLiteral("Combination");
    case AttackModeNum::BruteForceMask: return QStringLiteral("Brute-force / Mask");
    case AttackModeNum::HybridWordMask: return QStringLiteral("Hybrid Wordlist + Mask");
    case AttackModeNum::HybridMaskWord: return QStringLiteral("Hybrid Mask + Wordlist");
    default:                            return QStringLiteral("Mode %1").arg(attackMode);
    }
}

} // namespace forensic
