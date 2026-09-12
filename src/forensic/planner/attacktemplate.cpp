/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "attacktemplate.h"

namespace forensic {

QString attackTemplateName(AttackTemplate t)
{
    switch (t) {
    case AttackTemplate::QuickAttempt:            return QStringLiteral("Quick Attempt");
    case AttackTemplate::CommonPasswords:         return QStringLiteral("Common Passwords");
    case AttackTemplate::CaseWordlist:            return QStringLiteral("Case Wordlist");
    case AttackTemplate::WordlistRules:           return QStringLiteral("Wordlist + Rules");
    case AttackTemplate::KnownPasswordVariations: return QStringLiteral("Known Password Variations");
    case AttackTemplate::MaskAttack:              return QStringLiteral("Mask Attack");
    case AttackTemplate::HybridAttack:            return QStringLiteral("Hybrid Attack");
    case AttackTemplate::CustomAdvanced:          return QStringLiteral("Custom / Advanced");
    }
    return QStringLiteral("Custom / Advanced");
}

} // namespace forensic
