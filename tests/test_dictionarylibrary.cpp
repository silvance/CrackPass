/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/dictionary/dictionarylibrary.h"
#include "forensic/hashingservice.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestDictionaryLibrary : public QObject
{
    Q_OBJECT

private:
    static QString write(const QString &path, const QByteArray &bytes)
    {
        QFile f(path);
        f.open(QIODevice::WriteOnly | QIODevice::Truncate);
        f.write(bytes);
        f.close();
        return path;
    }
    static QByteArray read(const QString &path)
    {
        QFile f(path);
        f.open(QIODevice::ReadOnly);
        return f.readAll();
    }

    // Writes a bundled builtin manifest declaring CaseKey Common/Quick under
    // `dir`, creating only the files named in `presentFiles`.
    static QString writeBuiltinManifest(const QString &dir, const QStringList &presentFiles)
    {
        const QString manifest = QDir(dir).filePath("manifest.json");
        write(manifest, R"({
          "version": 1,
          "dictionaries": [
            {"id":"casekey-common","displayName":"CaseKey Common","description":"d","path":"casekey-common.txt","source":"CaseKey contributors","license":"GPL-3.0-or-later"},
            {"id":"casekey-quick","displayName":"CaseKey Quick","description":"d","path":"casekey-quick.txt","source":"CaseKey contributors","license":"GPL-3.0-or-later"}
          ]
        })");
        for (const QString &f : presentFiles)
            write(QDir(dir).filePath(f), "password\n123456\n");
        return manifest;
    }

private slots:
    void builtinsDiscoveredWithPresenceFlags();
    void candidateCountIgnoresBlankLinesAndHandlesNoTrailingNewline();
    void importReferenceInPlaceRecordsProvenance();
    void importCopyPreservesOriginal();
    void importedEntryPersistsAcrossReload();
    void checkIntegrityDetectsModificationAndMissing();
    void removeImportedDeletesCopyButKeepsReferencedOriginal();
    void builtinCannotBeRemoved();
    void revalidateRerecordsImportedBaseline();
    void defaultPrefersCaseKeyCommonWhenPresent();
    void buildsWhenBuiltinFilesAbsent();
};

void TestDictionaryLibrary::builtinsDiscoveredWithPresenceFlags()
{
    QTemporaryDir res, lib;
    const QString manifest = writeBuiltinManifest(res.path(), {"casekey-common.txt"});

    DictionaryLibrary d;
    d.setBuiltinManifest(manifest);
    d.setLibraryDir(lib.path());
    QVERIFY(d.reload());

    QCOMPARE(d.entries().size(), 2);
    bool found = false;
    const DictionaryEntry common = d.entry("casekey-common", &found);
    QVERIFY(found);
    QCOMPARE(common.displayName, QStringLiteral("CaseKey Common"));
    QVERIFY(common.isBuiltin());
    QVERIFY(common.fileExists());               // file was supplied
    QCOMPARE(common.source, QStringLiteral("CaseKey contributors"));

    const DictionaryEntry quick = d.entry("casekey-quick", &found);
    QVERIFY(found);
    QVERIFY(!quick.fileExists());               // file supplied separately, absent here

    // presentEntries() filters to on-disk files only.
    QCOMPARE(d.presentEntries().size(), 1);
}

void TestDictionaryLibrary::candidateCountIgnoresBlankLinesAndHandlesNoTrailingNewline()
{
    QTemporaryDir dir;
    // Blank line in the middle is not a candidate; a whitespace-only line is.
    QCOMPARE(DictionaryLibrary::countCandidates(
                 write(dir.filePath("a.txt"), "alpha\nbravo\n\ncharlie\n")), 3);
    // No trailing newline: the last line still counts.
    QCOMPARE(DictionaryLibrary::countCandidates(
                 write(dir.filePath("b.txt"), "one\ntwo\nthree")), 3);
    // CRLF line endings.
    QCOMPARE(DictionaryLibrary::countCandidates(
                 write(dir.filePath("c.txt"), "x\r\ny\r\n")), 2);
    // A line of spaces is a (deliberate) candidate; a bare newline is not.
    QCOMPARE(DictionaryLibrary::countCandidates(
                 write(dir.filePath("d.txt"), "  \n\n")), 1);
    // Empty file.
    QCOMPARE(DictionaryLibrary::countCandidates(write(dir.filePath("e.txt"), "")), 0);

    QString err;
    QCOMPARE(DictionaryLibrary::countCandidates("/no/such/file.txt", &err), qint64(-1));
    QVERIFY(!err.isEmpty());
}

void TestDictionaryLibrary::importReferenceInPlaceRecordsProvenance()
{
    QTemporaryDir src, lib;
    const QByteArray body = "letmein\nhunter2\nswordfish\n";
    const QString wl = write(src.filePath("mylist.txt"), body);
    const QString expectSha =
        QString::fromLatin1(QCryptographicHash::hash(body, QCryptographicHash::Sha256).toHex());

    DictionaryLibrary d;
    d.setLibraryDir(lib.path());
    QVERIFY(d.reload());

    QString err;
    const QString id = d.importWordlist(wl, "My List", "desc", "a colleague", "unknown",
                                        /*copyIntoLibrary=*/false, &err);
    QVERIFY2(!id.isEmpty(), qPrintable(err));

    bool found = false;
    const DictionaryEntry e = d.entry(id, &found);
    QVERIFY(found);
    QCOMPARE(e.origin, DictionaryOrigin::Imported);
    QCOMPARE(e.sha256, expectSha);
    QCOMPARE(e.candidateCount, qint64(3));
    QCOMPARE(e.sizeBytes, qint64(body.size()));
    QVERIFY(!e.copiedIntoLibrary);
    QCOMPARE(e.absolutePath, QFileInfo(wl).absoluteFilePath()); // referenced in place
    QCOMPARE(e.source, QStringLiteral("a colleague"));
    // The original was not modified.
    QCOMPARE(read(wl), body);
}

void TestDictionaryLibrary::importCopyPreservesOriginal()
{
    QTemporaryDir src, lib;
    const QByteArray body = "aaa\nbbb\n";
    const QString wl = write(src.filePath("orig.txt"), body);

    DictionaryLibrary d;
    d.setLibraryDir(lib.path());
    QVERIFY(d.reload());

    QString err;
    const QString id = d.importWordlist(wl, "Copied", "", "", "",
                                        /*copyIntoLibrary=*/true, &err);
    QVERIFY2(!id.isEmpty(), qPrintable(err));

    const DictionaryEntry e = d.entry(id);
    QVERIFY(e.copiedIntoLibrary);
    QVERIFY(e.absolutePath.startsWith(QDir(lib.path()).absolutePath())); // lives in library
    QVERIFY(QFileInfo::exists(e.absolutePath));
    QCOMPARE(read(e.absolutePath), body);      // copy has the same content
    // Original still there and unchanged.
    QVERIFY(QFileInfo::exists(wl));
    QCOMPARE(read(wl), body);
}

void TestDictionaryLibrary::importedEntryPersistsAcrossReload()
{
    QTemporaryDir src, lib;
    const QString wl = write(src.filePath("w.txt"), "p1\np2\n");

    QString id;
    {
        DictionaryLibrary d;
        d.setLibraryDir(lib.path());
        QVERIFY(d.reload());
        QString err;
        id = d.importWordlist(wl, "Persisted", "", "src", "lic", false, &err);
        QVERIFY2(!id.isEmpty(), qPrintable(err));
    }
    // A fresh library over the same directory sees the imported entry.
    DictionaryLibrary d2;
    d2.setLibraryDir(lib.path());
    QVERIFY(d2.reload());
    bool found = false;
    const DictionaryEntry e = d2.entry(id, &found);
    QVERIFY(found);
    QCOMPARE(e.displayName, QStringLiteral("Persisted"));
    QCOMPARE(e.candidateCount, qint64(2));
    QCOMPARE(e.source, QStringLiteral("src"));
}

void TestDictionaryLibrary::checkIntegrityDetectsModificationAndMissing()
{
    QTemporaryDir src, lib;
    const QString wl = write(src.filePath("w.txt"), "one\ntwo\n");

    DictionaryLibrary d;
    d.setLibraryDir(lib.path());
    QVERIFY(d.reload());
    QString err;
    const QString id = d.importWordlist(wl, "W", "", "", "", false, &err);
    QVERIFY2(!id.isEmpty(), qPrintable(err));

    // Unchanged -> Present.
    QCOMPARE(d.checkIntegrity(id), DictionaryLibrary::IntegrityStatus::Present);

    // Modify the referenced file -> Modified, and the current digest differs.
    write(wl, "one\ntwo\nthree\n");
    QString current;
    QCOMPARE(d.checkIntegrity(id, &current), DictionaryLibrary::IntegrityStatus::Modified);
    QCOMPARE(current.size(), 64);
    QVERIFY(current != d.entry(id).sha256);

    // Remove the file -> Missing.
    QFile::remove(wl);
    QCOMPARE(d.checkIntegrity(id), DictionaryLibrary::IntegrityStatus::Missing);
}

void TestDictionaryLibrary::removeImportedDeletesCopyButKeepsReferencedOriginal()
{
    QTemporaryDir src, lib;

    DictionaryLibrary d;
    d.setLibraryDir(lib.path());
    QVERIFY(d.reload());
    QString err;

    // Copy import: removal deletes the library-owned copy.
    const QString copyWl = write(src.filePath("copy.txt"), "c\n");
    const QString copyId = d.importWordlist(copyWl, "Copy", "", "", "", true, &err);
    QVERIFY2(!copyId.isEmpty(), qPrintable(err));
    const QString copyPath = d.entry(copyId).absolutePath;
    QVERIFY(QFileInfo::exists(copyPath));
    QVERIFY(d.removeImported(copyId, &err));
    QVERIFY(!d.contains(copyId));
    QVERIFY(!QFileInfo::exists(copyPath));      // copy deleted

    // Reference import: removal must not delete the examiner's original.
    const QString refWl = write(src.filePath("ref.txt"), "r\n");
    const QString refId = d.importWordlist(refWl, "Ref", "", "", "", false, &err);
    QVERIFY2(!refId.isEmpty(), qPrintable(err));
    QVERIFY(d.removeImported(refId, &err));
    QVERIFY(!d.contains(refId));
    QVERIFY(QFileInfo::exists(refWl));          // original preserved
}

void TestDictionaryLibrary::builtinCannotBeRemoved()
{
    QTemporaryDir res, lib;
    const QString manifest = writeBuiltinManifest(res.path(), {"casekey-common.txt"});
    DictionaryLibrary d;
    d.setBuiltinManifest(manifest);
    d.setLibraryDir(lib.path());
    QVERIFY(d.reload());

    QString err;
    QVERIFY(!d.removeImported("casekey-common", &err));
    QVERIFY(!err.isEmpty());
    QVERIFY(d.contains("casekey-common"));      // still there
}

void TestDictionaryLibrary::revalidateRerecordsImportedBaseline()
{
    QTemporaryDir src, lib;
    const QString wl = write(src.filePath("w.txt"), "one\ntwo\n");

    DictionaryLibrary d;
    d.setLibraryDir(lib.path());
    QVERIFY(d.reload());
    QString err;
    const QString id = d.importWordlist(wl, "W", "", "", "", false, &err);
    QVERIFY2(!id.isEmpty(), qPrintable(err));
    QCOMPARE(d.entry(id).candidateCount, qint64(2));

    // Modify the referenced file -> drift detected.
    write(wl, "one\ntwo\nthree\nfour\n");
    QCOMPARE(d.checkIntegrity(id), DictionaryLibrary::IntegrityStatus::Modified);

    // Revalidate re-records the new baseline: integrity is Present again and the
    // count reflects the new content.
    qint64 count = -1;
    QString sha;
    QVERIFY2(d.revalidate(id, &count, &sha, &err), qPrintable(err));
    QCOMPARE(count, qint64(4));
    QCOMPARE(sha.size(), 64);
    QCOMPARE(d.checkIntegrity(id), DictionaryLibrary::IntegrityStatus::Present);
    QCOMPARE(d.entry(id).candidateCount, qint64(4));

    // Persisted: a fresh library over the same dir sees the updated baseline.
    DictionaryLibrary d2;
    d2.setLibraryDir(lib.path());
    QVERIFY(d2.reload());
    QCOMPARE(d2.entry(id).candidateCount, qint64(4));
    QCOMPARE(d2.entry(id).sha256, sha);

    // Revalidating a missing file fails cleanly.
    QFile::remove(wl);
    QVERIFY(!d.revalidate(id, nullptr, nullptr, &err));
    QVERIFY(!err.isEmpty());
}

void TestDictionaryLibrary::defaultPrefersCaseKeyCommonWhenPresent()
{
    QTemporaryDir res, lib;
    // Both builtins present -> default is CaseKey Common, requiring no case
    // knowledge to select.
    const QString manifest =
        writeBuiltinManifest(res.path(), {"casekey-common.txt", "casekey-quick.txt"});
    DictionaryLibrary d;
    d.setBuiltinManifest(manifest);
    d.setLibraryDir(lib.path());
    QVERIFY(d.reload());
    QCOMPARE(d.defaultEntryId(), QStringLiteral("casekey-common"));
}

void TestDictionaryLibrary::buildsWhenBuiltinFilesAbsent()
{
    // The manifest is present but neither wordlist file is -- the library must
    // still load, expose the entries, and report none as present (no fabricated
    // data). The default falls back to the first declared entry so the UI can
    // explain that its file must be supplied.
    QTemporaryDir res, lib;
    const QString manifest = writeBuiltinManifest(res.path(), {});
    DictionaryLibrary d;
    d.setBuiltinManifest(manifest);
    d.setLibraryDir(lib.path());
    QVERIFY(d.reload());
    QCOMPARE(d.entries().size(), 2);
    QVERIFY(d.presentEntries().isEmpty());
    QCOMPARE(d.defaultEntryId(), QStringLiteral("casekey-common"));
}

QTEST_GUILESS_MAIN(TestDictionaryLibrary)
#include "test_dictionarylibrary.moc"
