/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Vertical-slice test for the primary use case: recovering an encrypted Office
 * document's password with the managed dictionary library and no case
 * knowledge. This exercises the planning + engine-selection path headlessly (it
 * needs no external tools, so it always runs in CI); the LIVE crack of a
 * synthetic encrypted .docx with a real hashcat + office2john is covered by the
 * optional real-tool integration test (tests/integration), which QSKIPs when
 * those tools and a corpus are absent.
 */
#include "forensic/dictionary/dictionarylibrary.h"
#include "forensic/planner/attackplanner.h"
#include "forensic/recovery/recoveryengineregistry.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

// hashcat mode for MS Office 2013 (agile encryption) documents.
static constexpr quint32 kOffice2013Mode = 9600;

class TestOfficeDictionarySlice : public QObject
{
    Q_OBJECT
private:
    static void write(const QString &path, const QByteArray &bytes)
    {
        QFile f(path);
        f.open(QIODevice::WriteOnly | QIODevice::Truncate);
        f.write(bytes);
        f.close();
    }

    // A dictionary library whose "CaseKey Common" builtin points at a real
    // (test-authored) wordlist containing the known password among decoys.
    static QString writeLibrary(const QString &dir, const QString &password)
    {
        const QString manifest = QDir(dir).filePath("manifest.json");
        write(manifest, R"({
          "version": 1,
          "dictionaries": [
            {"id":"casekey-common","displayName":"CaseKey Common","description":"d","path":"casekey-common.txt","source":"test","license":"GPL-3.0-or-later"}
          ]
        })");
        write(QDir(dir).filePath("casekey-common.txt"),
              ("decoy1\n" + password + "\ndecoy2\n").toUtf8());
        return manifest;
    }

private slots:
    void dictionaryOfficeRecoveryNeedsNoCaseKnowledge();
};

void TestOfficeDictionarySlice::dictionaryOfficeRecoveryNeedsNoCaseKnowledge()
{
    QTemporaryDir res;
    const QString manifest = writeLibrary(res.path(), QStringLiteral("Sunshine2020"));

    // 1) The managed library offers CaseKey Common as the default, with its file
    //    present, so the examiner can start a Dictionary attack knowing nothing
    //    about the case.
    DictionaryLibrary lib;
    lib.setBuiltinManifest(manifest);
    lib.setLibraryDir(res.filePath("library")); // writable side (unused here)
    QVERIFY(lib.reload());
    QCOMPARE(lib.defaultEntryId(), QStringLiteral("casekey-common"));
    bool found = false;
    const DictionaryEntry dict = lib.entry(lib.defaultEntryId(), &found);
    QVERIFY(found);
    QVERIFY(dict.fileExists());

    // 2) Plan a Dictionary attack against an Office 2013 hash using that
    //    dictionary and EMPTY case knowledge -- the default path must require
    //    none.
    PlannerContext ctx;
    ctx.hashMode = kOffice2013Mode;
    ctx.hashTypeName = QStringLiteral("MS Office 2013");
    ctx.hashFile = QDir(res.path()).filePath("office.hash");
    ctx.planDir = res.filePath("plan");
    ctx.commonWordlist = dict.absolutePath;

    const PlanResult plan = AttackPlanner().plan(AttackTemplate::CommonPasswords,
                                                 CaseKnowledge{}, ctx);
    QVERIFY2(plan.ok, qPrintable(plan.error));
    QCOMPARE(plan.spec.hashMode, kOffice2013Mode);
    QCOMPARE(plan.spec.attackMode, int(AttackModeNum::Straight));
    QCOMPARE(plan.spec.wordlists, QStringList{dict.absolutePath});
    QVERIFY(plan.spec.rules.isEmpty());       // a plain dictionary pass
    QVERIFY(plan.generatedFiles.isEmpty());   // nothing had to be materialised

    // 3) The engine is chosen automatically -- hashcat expresses this attack.
    const RecoveryEngineRegistry engines = RecoveryEngineRegistry::withBuiltins();
    const RecoveryEngine *engine = engines.selectForSpec(plan.spec);
    QVERIFY(engine != nullptr);
    QCOMPARE(engine->id(), QStringLiteral("hashcat"));

    // 4) The resulting command targets the Office mode with the managed
    //    dictionary -- the exact, reproducible thing that would run.
    const QStringList args = engine->buildArgs(plan.spec);
    const int m = args.indexOf(QStringLiteral("-m"));
    QVERIFY(m >= 0);
    QCOMPARE(args.value(m + 1), QString::number(kOffice2013Mode));
    const int a = args.indexOf(QStringLiteral("-a"));
    QVERIFY(a >= 0);
    QCOMPARE(args.value(a + 1), QStringLiteral("0")); // straight/dictionary
    QVERIFY(args.contains(dict.absolutePath));
    QVERIFY(args.contains(ctx.hashFile));
}

QTEST_GUILESS_MAIN(TestOfficeDictionarySlice)
#include "test_officedictionaryslice.moc"
