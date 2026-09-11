/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "attackplanner.h"
#include "attackcommandbuilder.h"
#include "knowledgematerializer.h"

#include <QDir>

namespace forensic {

namespace {

// Materialize a case-knowledge wordlist into planDir; returns its path or empty.
QString makeCaseWordlist(const CaseKnowledge &k, const QString &planDir, QStringList &generated, QString *error)
{
    if (planDir.isEmpty()) {
        if (error) *error = QStringLiteral("No plan directory available to write generated files.");
        return QString();
    }
    QDir().mkpath(planDir);
    const QString path = QDir(planDir).filePath(QStringLiteral("case_wordlist.txt"));
    if (!KnowledgeMaterializer::writeWordlist(k, path, error))
        return QString();
    generated << path;
    return path;
}

QString makeCaseRules(const CaseKnowledge &k, const QString &planDir, QStringList &generated, QString *error)
{
    if (planDir.isEmpty()) {
        if (error) *error = QStringLiteral("No plan directory available to write generated files.");
        return QString();
    }
    QDir().mkpath(planDir);
    const QString path = QDir(planDir).filePath(QStringLiteral("case_rules.rule"));
    if (!KnowledgeMaterializer::writeRules(k, path, error))
        return QString();
    generated << path;
    return path;
}

} // namespace

AttackPreview AttackPlanner::buildPreview(AttackTemplate templ, const AttackJobSpec &spec,
                                          const PlannerContext &ctx) const
{
    AttackPreview p;
    p.templateName = attackTemplateName(templ);
    p.hashTypeName = ctx.hashTypeName;
    p.hashMode = spec.hashMode;
    p.attackMode = spec.attackMode;
    p.attackModeName = attackModeName(spec.attackMode);
    p.wordlists = spec.wordlists;
    p.rules = spec.rules;
    p.mask = spec.mask;
    p.estimatedKeyspace = KnowledgeMaterializer::estimateKeyspace(spec);
    p.devices = ctx.devices;
    p.command = AttackCommandBuilder::buildCommand(spec);
    return p;
}

PlanResult AttackPlanner::plan(AttackTemplate templ, const CaseKnowledge &knowledge,
                               const PlannerContext &ctx) const
{
    PlanResult result;
    AttackJobSpec spec;
    spec.hashMode = ctx.hashMode;
    spec.hashFile = ctx.hashFile;

    QString err;

    switch (templ) {
    case AttackTemplate::QuickAttempt: {
        spec.attackMode = AttackModeNum::Straight;
        if (!ctx.commonWordlist.isEmpty()) {
            spec.wordlists << ctx.commonWordlist;
        } else {
            const QString wl = makeCaseWordlist(knowledge, ctx.planDir, result.generatedFiles, &err);
            if (wl.isEmpty()) {
                result.error = QStringLiteral(
                    "Quick Attempt needs a common-password wordlist or some case words. %1").arg(err);
                return result;
            }
            spec.wordlists << wl;
        }
        spec.notes = QStringLiteral("Fast dictionary pass, no rules.");
        break;
    }
    case AttackTemplate::CommonPasswords: {
        spec.attackMode = AttackModeNum::Straight;
        if (ctx.commonWordlist.isEmpty()) {
            result.error = QStringLiteral("No common-password wordlist is configured.");
            return result;
        }
        spec.wordlists << ctx.commonWordlist;
        break;
    }
    case AttackTemplate::CaseWordlist: {
        spec.attackMode = AttackModeNum::Straight;
        const QString wl = makeCaseWordlist(knowledge, ctx.planDir, result.generatedFiles, &err);
        if (wl.isEmpty()) { result.error = err; return result; }
        spec.wordlists << wl;
        break;
    }
    case AttackTemplate::WordlistRules: {
        spec.attackMode = AttackModeNum::Straight;
        QString wl = ctx.commonWordlist;
        if (wl.isEmpty()) {
            wl = makeCaseWordlist(knowledge, ctx.planDir, result.generatedFiles, &err);
            if (wl.isEmpty()) { result.error = err; return result; }
        }
        spec.wordlists << wl;
        const QString rules = makeCaseRules(knowledge, ctx.planDir, result.generatedFiles, &err);
        if (rules.isEmpty()) { result.error = err; return result; }
        spec.rules << rules;
        break;
    }
    case AttackTemplate::KnownPasswordVariations: {
        spec.attackMode = AttackModeNum::Straight;
        if (!knowledge.hasAnyWordSeed()) {
            result.error = QStringLiteral(
                "Known Password Variations needs suspected base words, names, or previous passwords.");
            return result;
        }
        const QString wl = makeCaseWordlist(knowledge, ctx.planDir, result.generatedFiles, &err);
        if (wl.isEmpty()) { result.error = err; return result; }
        const QString rules = makeCaseRules(knowledge, ctx.planDir, result.generatedFiles, &err);
        if (rules.isEmpty()) { result.error = err; return result; }
        spec.wordlists << wl;
        spec.rules << rules;
        break;
    }
    case AttackTemplate::MaskAttack: {
        spec.attackMode = AttackModeNum::BruteForceMask;
        const MaskResult mask = KnowledgeMaterializer::buildMask(knowledge);
        if (!mask.ok) { result.error = mask.reason; return result; }
        spec.mask = mask.mask;
        spec.customCharset1 = mask.customCharset1;
        if (knowledge.minLength > 0 && knowledge.maxLength > knowledge.minLength) {
            spec.increment = true;
            spec.incrementMin = knowledge.minLength;
            spec.incrementMax = knowledge.maxLength;
        }
        break;
    }
    case AttackTemplate::HybridAttack: {
        spec.attackMode = AttackModeNum::HybridWordMask;
        QString wl = ctx.commonWordlist;
        if (wl.isEmpty()) {
            wl = makeCaseWordlist(knowledge, ctx.planDir, result.generatedFiles, &err);
            if (wl.isEmpty()) { result.error = err; return result; }
        }
        spec.wordlists << wl;
        // Appended part: a year range implies a 4-digit tail; otherwise default
        // to a common 2-4 digit tail.
        spec.mask = QStringLiteral("?d?d?d?d");
        spec.notes = QStringLiteral("Wordlist with an appended digit mask (e.g. years).");
        break;
    }
    case AttackTemplate::CustomAdvanced: {
        spec.attackMode = AttackModeNum::Straight;
        spec.extraArgs = ctx.customArgs;
        spec.notes = QStringLiteral(
            "Pass-through: edit freely here or in Advanced Hashcat Mode.");
        break;
    }
    }

    result.ok = true;
    result.spec = spec;
    result.preview = buildPreview(templ, spec, ctx);
    return result;
}

} // namespace forensic
