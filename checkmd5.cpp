#include "checkmd5.h"
#include "md5.h"
#include "version.h"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTextStream>
#include <QTimer>
#include <QThreadPool>
#include <QMutex>
#include <QQueue>
#include <QSemaphore>
#include <QAtomicInteger>

#include <algorithm>
#include <csignal>

static volatile std::sig_atomic_t g_signalRaised = 0;

namespace {

constexpr int MD5_HASH_LENGTH = 32;
constexpr int MIN_CHECKSUM_LINE_LENGTH = MD5_HASH_LENGTH + 2;
constexpr int HASH_BUFFER_SIZE = 256 * 1024;
constexpr int PROGRESS_STEPS = 1000;
constexpr float MIN_PERCENT = 0.0F;
constexpr float MAX_PERCENT = 100.0F;

// How often the dispatcher wakes to refresh progress while workers are busy.
// Completions wake it immediately via the semaphore; this only bounds how stale
// the progress percentage can get during a long single-file hash.
constexpr int PROGRESS_REFRESH_MS = 20;

} // namespace

void signalHandler(int signal)
{
    g_signalRaised = signal;
}

CheckMD5::CheckMD5(QObject* parent)
    : QObject(parent)
{
    // Install signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGHUP, signalHandler);
}

ExitCode CheckMD5::run(const QStringList& arguments)
{
    QCommandLineParser parser;
    parser.setApplicationDescription(
        QCoreApplication::translate("CheckMD5", "Tool for checking the integrity of multiple files as one unit."));
    parser.addHelpOption();
    parser.addVersionOption();

    // Define command line options
    QCommandLineOption forceOption("force",
                                   QCoreApplication::translate("CheckMD5", "Continue checking even if errors occur."));
    QCommandLineOption verboseOption("verbose", QCoreApplication::translate("CheckMD5", "Show verbose output."));
    QCommandLineOption machineOption("machine",
                                     QCoreApplication::translate("CheckMD5", "Machine-readable output format."));
    QCommandLineOption logOption("log", QCoreApplication::translate("CheckMD5", "Log output to file."), "file");
    QCommandLineOption jobsOption(QStringList() << "jobs",
                                  QCoreApplication::translate("CheckMD5",
                                                                "Number of files to hash in parallel (0 = auto)."),
                                  "count");

    parser.addOption(forceOption);
    parser.addOption(verboseOption);
    parser.addOption(machineOption);
    parser.addOption(logOption);
    parser.addOption(jobsOption);
    parser.addPositionalArgument("files", QCoreApplication::translate("CheckMD5", "MD5 checksum files to verify."),
                                 "file1 [file2...]");

    // Parse arguments
    if (!parser.parse(arguments)) {
        qCritical().noquote() << parser.errorText();
        return ExitCode::System;
    }

    if (parser.isSet("help")) {
        parser.showHelp();
        return ExitCode::Ok;
    }

    if (parser.isSet("version")) {
        parser.showVersion();
        return ExitCode::Ok;
    }

    // Set options from parsed arguments
    m_force = parser.isSet(forceOption);
    m_verbose = parser.isSet(verboseOption);
    m_machine = parser.isSet(machineOption);
    m_logFile = parser.value(logOption);

    m_jobs = 1;
    if (parser.isSet(jobsOption)) {
        bool ok = false;
        const int parsedJobs = parser.value(jobsOption).toInt(&ok);
        if (!ok || parsedJobs < 0) {
            qCritical().noquote() << QCoreApplication::translate("CheckMD5", "Invalid value for --jobs.");
            return ExitCode::System;
        }
        m_jobs = parsedJobs;
    }

    // Setup logging
    if (!m_logFile.isEmpty()) {
        QFile* logFile = new QFile(m_logFile, this);
        if (!logFile->open(QIODevice::WriteOnly | QIODevice::Text)) {
            qCritical().noquote() << "ERROR: Cannot open log file:" << m_logFile;
            return ExitCode::System;
        }
        m_logStream = std::make_unique<QTextStream>(logFile);
    }

    // Get positional arguments (checksum files)
    QStringList sumFiles = parser.positionalArguments();

    if (sumFiles.isEmpty()) {
        qCritical().noquote() << QCoreApplication::translate("CheckMD5", "No checksum files specified.");
        parser.showHelp();
        return ExitCode::System;
    }

    // Log start time and files
    const QString startTime = QDateTime::currentDateTime().toString();
    logMessage(false, QString("Start: %1\nLists:").arg(startTime));
    for (const QString& file : sumFiles) {
        logMessage(false, QString(" %1").arg(file));
    }
    logMessage(false, "\n");

    // Load targets
    auto targets = loadTargets(sumFiles);
    if (targets.isEmpty()) {
        logMessage(false, "Exit: 3\n");
        return ExitCode::BadList;
    }

    // Check files
    int jobCount = m_jobs;
    if (jobCount == 0) {
        jobCount = QThreadPool::globalInstance()->maxThreadCount();
    }
    jobCount = qMax(1, jobCount);

    m_nextProgressUpdate = 0;
    m_lastNotifiedProgress = 0;
    m_lastShownPercent = -1;
    ExitCode result = jobCount > 1 ? checkFilesParallel(targets, jobCount) : checkFiles(targets);

    // Display result message (non-machine mode)
    if (!m_machine) {
        switch (result) {
        case ExitCode::Ok:
            qInfo().noquote() << QCoreApplication::translate("CheckMD5", "The integrity check has passed.");
            break;
        case ExitCode::BadCheck:
            qWarning().noquote() << QCoreApplication::translate("CheckMD5", "The integrity check has failed.");
            break;
        case ExitCode::Aborted:
            qWarning().noquote() << QCoreApplication::translate("CheckMD5", "The integrity check was aborted.");
            break;
        default:
            qCritical().noquote() << QCoreApplication::translate("CheckMD5",
                                                                 "The integrity check could not be completed.");
            break;
        }
    }

    logMessage(false, QString("Exit: %1\n").arg(static_cast<int>(result)));
    return result;
}

QList<CheckTarget> CheckMD5::loadTargets(const QStringList& sumFiles)
{
    QList<CheckTarget> targets;

    for (QString filename : sumFiles) {
        // Auto-append .md5 extension if not present
        if (!filename.endsWith(".md5", Qt::CaseInsensitive)) {
            qInfo().noquote() << QCoreApplication::translate("CheckMD5", "Note: Appending .md5 extension to")
                              << filename;
            filename += ".md5";
        }

        QFile file(filename);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            logMessage(true, QString("ERROR: %1: %2\n").arg(file.errorString(), filename));
            return {};
        }

        QTextStream stream(&file);
        int lineNumber = 0;

        // Base directory is identical for every line in this list, so resolve it once.
        const QFileInfo md5FileInfo(filename);
        const QDir baseDir(md5FileInfo.absolutePath());

        while (!stream.atEnd()) {
            QString line = stream.readLine();
            ++lineNumber;

            // Trim whitespace
            line = line.trimmed();

            if (line.length() < MIN_CHECKSUM_LINE_LENGTH) {
                logMessage(true, QString("ERROR (%1 line %2): Line too short.\n").arg(filename).arg(lineNumber));
                return {};
            }

            QString hash = line.left(MD5_HASH_LENGTH).toUpper();
            static const QRegularExpression hexRegex(QString("^[0-9A-F]{%1}$").arg(MD5_HASH_LENGTH));
            if (!hexRegex.match(hash).hasMatch()) {
                logMessage(
                    true,
                    QString("ERROR (%1 line %2): Invalid hex or too short for MD5.\n").arg(filename).arg(lineNumber));
                return {};
            }

            // Find the start of the path (skip spaces after hash)
            int pathStart = MD5_HASH_LENGTH;
            while (pathStart < line.length() && (line[pathStart] == ' ' || line[pathStart] == '\t')) {
                ++pathStart;
            }

            if (pathStart >= line.length()) {
                logMessage(true, QString("ERROR (%1 line %2): No space or path.\n").arg(filename).arg(lineNumber));
                return {};
            }

            QString path = line.mid(pathStart);

            // Resolve path relative to the directory containing the .md5 file
            QFileInfo fileInfo(baseDir.filePath(path));

            if (!fileInfo.exists()) {
                logMessage(true, QString("ERROR (%1 line %2): Cannot stat: %3\n")
                                     .arg(filename)
                                     .arg(lineNumber)
                                     .arg(fileInfo.absoluteFilePath()));
                return {};
            }

            CheckTarget target;
            target.hash = hash;
            target.path = fileInfo.absoluteFilePath(); // Use absolute path for checking
            target.size = fileInfo.size();

            targets.append(target);
        }
    }

    return targets;
}

ExitCode CheckMD5::checkFiles(const QList<CheckTarget>& targets)
{
    if (!m_machine) {
        qInfo().noquote() << QCoreApplication::translate("CheckMD5", "Press [Ctrl+C] to abort the integrity check.");
    }

    // Calculate total size
    qint64 totalSize = 0;
    std::for_each(targets.cbegin(), targets.cend(),
                  [&totalSize](const CheckTarget& target) { totalSize += target.size; });

    // Check each file
    int passed = 0;
    qint64 processedSize = 0;
    qint64 passedSize = 0;
    ExitCode result = ExitCode::Ok;

    for (const auto& target : targets) {
        logMessage(m_verbose, QString("Target: %1 %2\n").arg(target.hash, target.path));

        QFile file(target.path);
        if (!file.open(QIODevice::ReadOnly)) {
            logMessage(true, QString("%1: %2\n").arg(file.errorString(), target.path));
            result = ExitCode::BadCheck;
            if (!m_force) {
                break;
            }
            processedSize += target.size;
            continue;
        }

        updateProgress(processedSize, totalSize);

        MD5 hasher;
        bool fileAborted = false;
        QByteArray buffer(HASH_BUFFER_SIZE, Qt::Uninitialized);
        while (!file.atEnd()) {
            if (checkForAbort()) {
                result = ExitCode::Aborted;
                fileAborted = true;
                break;
            }

            const qint64 bytesRead = file.read(buffer.data(), HASH_BUFFER_SIZE);
            if (bytesRead <= 0) {
                break;
            }
            hasher.update(reinterpret_cast<const uint8_t*>(buffer.constData()), static_cast<size_t>(bytesRead));
            processedSize += bytesRead;

            updateProgress(processedSize, totalSize);
        }

        if (fileAborted) {
            file.close();
            break;
        }

        const QFileDevice::FileError readError = file.error();
        const QString readErrorString = file.errorString();
        file.close();

        if (readError != QFileDevice::NoError) {
            logMessage(true, QString("%1: %2\n").arg(readErrorString, target.path));
            result = ExitCode::BadCheck;
            if (!m_force) {
                break;
            }
            continue;
        }

        if (m_verbose && !m_machine) {
            qInfo().noquote() << ""; // Break progress line
        }

        QByteArray digest = hasher.finalize();
        QString computedHash = digest.toHex().toUpper();

        bool matches = (target.hash == computedHash);
        logMessage(m_verbose, QString("%1: %2 %3\n").arg(matches ? "Passed" : "Failed", computedHash, target.path));

        if (matches) {
            ++passed;
            passedSize += target.size;
        } else {
            if (!m_verbose && !m_machine) {
                qInfo().noquote() << "";
            }
            qWarning().noquote() << QCoreApplication::translate("CheckMD5", "Checksum mismatch") << ":" << target.path;
            result = ExitCode::BadCheck;
            if (!m_force) {
                break;
            }
        }
    }

    if (!m_verbose && !m_machine) {
        qInfo().noquote() << ""; // Break progress line
    }

    logMessage(m_verbose, QString("Result: %1/%2 targets (%3/%4 bytes) passed\n")
                              .arg(passed)
                              .arg(targets.size())
                              .arg(passedSize)
                              .arg(totalSize));

    return result;
}

ExitCode CheckMD5::checkFilesParallel(const QList<CheckTarget>& targets, int jobCount)
{
    if (!m_machine) {
        qInfo().noquote() << QCoreApplication::translate("CheckMD5", "Press [Ctrl+C] to abort the integrity check.");
    }

    qint64 totalSize = 0;
    std::for_each(targets.cbegin(), targets.cend(),
                  [&totalSize](const CheckTarget& target) { totalSize += target.size; });

    QAtomicInteger<qint64> processedBytes = 0;
    QAtomicInteger<int> stopRequested = 0;

    struct WorkerResult {
        int index = 0;
        CheckTarget target;
        QString error;
        QByteArray digest;
        bool aborted = false;
        bool skipped = false;
    };

    // Workers push finished results onto this queue and signal the semaphore; the
    // dispatcher below wakes on each completion rather than polling on a timer.
    QMutex resultMutex;
    QQueue<WorkerResult> resultQueue;
    QSemaphore completed;

    auto task = [&resultMutex, &resultQueue, &completed, processedBytes = &processedBytes,
                 stopRequested = &stopRequested](int index, const CheckTarget& target) {
        WorkerResult workerResult;
        workerResult.index = index;
        workerResult.target = target;

        if (stopRequested->loadAcquire()) {
            workerResult.skipped = true;
        } else {
            QFile file(target.path);
            if (!file.open(QIODevice::ReadOnly)) {
                workerResult.error = file.errorString();
            } else {
                MD5 hasher;
                QByteArray buffer(HASH_BUFFER_SIZE, Qt::Uninitialized);
                while (!file.atEnd()) {
                    if (g_signalRaised) {
                        workerResult.aborted = true;
                        break;
                    }
                    if (stopRequested->loadAcquire()) {
                        workerResult.skipped = true;
                        break;
                    }

                    const qint64 bytesRead = file.read(buffer.data(), HASH_BUFFER_SIZE);
                    if (bytesRead < 0) {
                        workerResult.error = file.errorString();
                        break;
                    }
                    if (bytesRead == 0) {
                        break;
                    }

                    hasher.update(reinterpret_cast<const uint8_t*>(buffer.constData()),
                                  static_cast<size_t>(bytesRead));

                    processedBytes->fetchAndAddRelaxed(bytesRead);
                }

                if (workerResult.error.isEmpty() && file.error() != QFileDevice::NoError) {
                    workerResult.error = file.errorString();
                }

                file.close();

                if (!workerResult.aborted && !workerResult.skipped && workerResult.error.isEmpty()) {
                    workerResult.digest = hasher.finalize();
                }
            }
        }

        {
            QMutexLocker locker(&resultMutex);
            resultQueue.enqueue(workerResult);
        }
        completed.release();
    };

    QThreadPool pool;
    pool.setMaxThreadCount(jobCount);
    pool.setExpiryTimeout(-1);

    int nextTarget = 0;
    int remaining = 0;
    auto startNext = [&]() -> bool {
        if (nextTarget >= targets.size() || (!m_force && stopRequested.loadAcquire())) {
            return false;
        }

        const int index = nextTarget;
        pool.start([&task, &targets, index]() { task(index, targets.at(index)); });
        ++nextTarget;
        ++remaining;
        return true;
    };

    // Prime the pool with up to jobCount concurrent hashes.
    for (int i = 0; i < jobCount && startNext(); ++i) {
    }

    qint64 passedSize = 0;
    int passed = 0;
    ExitCode result = ExitCode::Ok;

    while (remaining > 0) {
        // Block until a worker finishes, waking every PROGRESS_REFRESH_MS to keep
        // the progress percentage current during a long-running hash.
        const bool gotResult = completed.tryAcquire(1, PROGRESS_REFRESH_MS);

        scheduleProgressUpdate(processedBytes.loadRelaxed(), totalSize);

        if (!gotResult) {
            continue;
        }

        WorkerResult workerResult;
        {
            QMutexLocker locker(&resultMutex);
            workerResult = resultQueue.dequeue();
        }
        --remaining;

        if (workerResult.aborted) {
            if (result != ExitCode::Aborted) {
                if (!m_machine) {
                    qInfo().noquote() << "";
                }
                logMessage(m_verbose, QString("Aborted: (signal %1)\n").arg(g_signalRaised));
                result = ExitCode::Aborted;
                stopRequested.storeRelease(1);
            }
            continue;
        }

        if (workerResult.skipped) {
            continue;
        }

        if (!workerResult.error.isEmpty()) {
            logMessage(true, QString("%1: %2\n").arg(workerResult.error, workerResult.target.path));
            result = ExitCode::BadCheck;
            if (!m_force) {
                stopRequested.storeRelease(1);
            } else {
                while (remaining < jobCount && startNext()) {
                }
            }
            continue;
        }

        logMessage(m_verbose, QString("Target: %1 %2\n").arg(workerResult.target.hash, workerResult.target.path));

        const QString computedHash = QString::fromLatin1(workerResult.digest.toHex().toUpper());
        const bool matches = (workerResult.target.hash == computedHash);

        logMessage(m_verbose, QString("%1: %2 %3\n").arg(matches ? "Passed" : "Failed", computedHash, workerResult.target.path));

        if (matches) {
            ++passed;
            passedSize += workerResult.target.size;
        } else {
            if (!m_verbose && !m_machine) {
                qInfo().noquote() << "";
            }
            qWarning().noquote() << QCoreApplication::translate("CheckMD5", "Checksum mismatch") << ":" << workerResult.target.path;
            result = ExitCode::BadCheck;
            if (!m_force) {
                stopRequested.storeRelease(1);
            }
        }

        while (remaining < jobCount && startNext()) {
        }
    }

    if (!m_verbose && !m_machine) {
        qInfo().noquote() << "";
    }

    scheduleProgressUpdate(totalSize, totalSize);

    logMessage(m_verbose, QString("Result: %1/%2 targets (%3/%4 bytes) passed\n")
                              .arg(passed)
                              .arg(targets.size())
                              .arg(passedSize)
                              .arg(totalSize));

    pool.waitForDone();

    return result;
}

void CheckMD5::scheduleProgressUpdate(qint64 processed, qint64 total)
{
    if (processed <= m_lastNotifiedProgress && processed < total) {
        return;
    }

    updateProgress(processed, total);
}

void CheckMD5::updateProgress(qint64 processed, qint64 total)
{
    if (processed >= m_nextProgressUpdate || processed >= total) {
        // Calculate percentage with bounds checking
        float percentage = total > 0 ? (MAX_PERCENT * processed) / total : MIN_PERCENT;
        percentage = qBound(MIN_PERCENT, percentage, MAX_PERCENT);

        // Report whole-integer percentages only, and only when the value
        // actually changes, so scripts reading --machine output don't get the
        // same percentage repeated on consecutive lines.
        const int wholePercent = qRound(percentage);
        if (wholePercent != m_lastShownPercent) {
            m_lastShownPercent = wholePercent;

            if (m_machine) {
                QTextStream(stdout) << wholePercent << "%\n";
            } else {
                QTextStream(stdout) << QCoreApplication::translate("CheckMD5", "Checking") << ": " << wholePercent
                                    << "%\r";
            }

            emit progressUpdated(percentage);
        }

        m_lastNotifiedProgress = processed;

        // Update next progress threshold - ensure we don't divide by zero
        if (total > 0) {
            qint64 nextDiv = qMax(total / PROGRESS_STEPS, qint64(1));
            m_nextProgressUpdate = ((processed / nextDiv) + 1) * nextDiv;
        } else {
            m_nextProgressUpdate = processed + 1;
        }
    }
}

bool CheckMD5::checkForAbort()
{
    if (g_signalRaised) {
        if (!m_machine) {
            qInfo().noquote() << "";
        }
        logMessage(m_verbose, QString("Aborted: (signal %1)\n").arg(g_signalRaised));
        return true;
    }
    return false;
}

void CheckMD5::logMessage(bool console, const QString& message)
{
    if (m_logStream) {
        *m_logStream << message;
        m_logStream->flush();
    }
    if (console) {
        qInfo().noquote() << message;
    }
}
