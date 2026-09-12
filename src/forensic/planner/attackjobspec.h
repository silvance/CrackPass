/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_ATTACKJOBSPEC_H
#define FORENSIC_ATTACKJOBSPEC_H

#include <QString>
#include <QStringList>

namespace forensic {

// hashcat attack-mode numbers (matching the existing GUI / hashcat).
namespace AttackModeNum {
constexpr int Straight = 0;
constexpr int Combination = 1;
constexpr int BruteForceMask = 3;
constexpr int HybridWordMask = 6;
constexpr int HybridMaskWord = 7;
}

QString attackModeName(int attackMode);

/*
 * A fully explicit description of one hashcat attack: mode, inputs (wordlists,
 * rules, mask, custom charsets) and options. It is produced by the planner and
 * consumed by AttackCommandBuilder. Nothing here is implicit -- what you see is
 * what hashcat will be told.
 */
struct AttackJobSpec
{
    quint32 hashMode = 0;
    int attackMode = AttackModeNum::Straight;
    QString hashFile;            // path to the extracted-hash file

    QStringList wordlists;
    QStringList rules;
    QString mask;
    QString customCharset1;
    QString customCharset2;
    QString customCharset3;
    QString customCharset4;

    bool increment = false;
    int incrementMin = 0;
    int incrementMax = 0;

    bool optimizedKernel = false;

    // Escape hatch for the Custom/Advanced template: extra raw hashcat args.
    QStringList extraArgs;

    QString notes;
};

} // namespace forensic

#endif // FORENSIC_ATTACKJOBSPEC_H
