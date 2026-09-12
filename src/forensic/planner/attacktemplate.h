/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_ATTACKTEMPLATE_H
#define FORENSIC_ATTACKTEMPLATE_H

#include <QString>

namespace forensic {

// Examiner-friendly attack templates. Each maps to concrete hashcat settings;
// none hides hashcat -- the generated command is always shown.
enum class AttackTemplate {
    QuickAttempt,            // small/common dictionary, no rules
    CommonPasswords,         // large common-password wordlist
    CaseWordlist,            // dictionary built from case knowledge
    WordlistRules,           // case/common wordlist + rules
    KnownPasswordVariations, // rules generated from suspected base words
    MaskAttack,              // structured mask from known structure
    HybridAttack,            // wordlist + mask (e.g. append years/digits)
    CustomAdvanced,          // pass-through to the low-level interface
};

QString attackTemplateName(AttackTemplate t);

} // namespace forensic

#endif // FORENSIC_ATTACKTEMPLATE_H
