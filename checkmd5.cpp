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

#include <algorithm>
#include <csignal>

static volatile std::sig_atomic_t g_signalRaised = 0;

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

    parser.addOption(forceOption);
    parser.addOption(verboseOption);
    parser.addOption(machineOption);
    parser.addOption(logOption);
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

    // Setup logging
    if (!m_logFile.isEmpty()) {
        QFile* logFile = new QFile(m_logFile, this);
        if (!logFile->open(QIODevice::WriteOnly | QIODevice::Text)) {
            qCritical().noquote() << "ERROR: Cannot open log file:" << m_logFile;
            return ExitCode::System;
        }
        m_logStream = new QTextStream(logFile);
        logFile->setParent(this);
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
    ExitCode result = checkFiles(targets);

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

        while (!stream.atEnd()) {
            QString line = stream.readLine();
            ++lineNumber;

            // Trim whitespace
            line = line.trimmed();

            // Minimum line: 32 hex chars + space + path
            if (line.length() < 34) {
                logMessage(true, QString("ERROR (%1 line %2): Line too short.\n").arg(filename).arg(lineNumber));
                return {};
            }

            // Extract and validate MD5 hash (first 32 characters)
            QString hash = line.left(32).toUpper();
            QRegularExpression hexRegex("^[0-9A-F]{32}$");
            if (!hexRegex.match(hash).hasMatch()) {
                logMessage(
                    true,
                    QString("ERROR (%1 line %2): Invalid hex or too short for MD5.\n").arg(filename).arg(lineNumber));
                return {};
            }

            // Find the start of the path (skip spaces after hash)
            int pathStart = 32;
            while (pathStart < line.length() && (line[pathStart] == ' ' || line[pathStart] == '\t')) {
                ++pathStart;
            }

            if (pathStart >= line.length()) {
                logMessage(true, QString("ERROR (%1 line %2): No space or path.\n").arg(filename).arg(lineNumber));
                return {};
            }

            QString path = line.mid(pathStart);

            // Resolve path relative to the directory containing the .md5 file
            QFileInfo md5FileInfo(filename);
            QString basePath = md5FileInfo.absolutePath();
            QFileInfo fileInfo(QDir(basePath).filePath(path));

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
        constexpr int bufferSize = 64 * 1024; // 64KB buffer

        bool fileAborted = false;
        while (!file.atEnd()) {
            if (checkForAbort()) {
                result = ExitCode::Aborted;
                fileAborted = true;
                break;
            }

            QByteArray buffer = file.read(bufferSize);
            hasher.update(buffer);
            processedSize += buffer.size();

            updateProgress(processedSize, totalSize);
        }

        file.close();

        if (fileAborted) {
            break;
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
            if (!m_verbose) {
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

void CheckMD5::updateProgress(qint64 processed, qint64 total)
{
    if (processed >= m_nextProgressUpdate || processed >= total) {
        // Calculate percentage with bounds checking
        float percentage = total > 0 ? (100.0F * processed) / total : 0.0F;
        percentage = qBound(0.0F, percentage, 100.0F);

        QString percentStr = QString::number(percentage, 'f', 1) + '%';

        if (m_machine) {
            qInfo().noquote() << percentStr;
        } else {
            QTextStream(stdout) << QCoreApplication::translate("CheckMD5", "Checking") << ": " << percentStr << '\r';
        }

        emit progressUpdated(percentage);

        // Update next progress threshold - ensure we don't divide by zero
        if (total > 0) {
            qint64 nextDiv = qMax(total / 1000, qint64(1));
            m_nextProgressUpdate = ((processed / nextDiv) + 1) * nextDiv;
        } else {
            m_nextProgressUpdate = processed + 1;
        }
    }
}

bool CheckMD5::checkForAbort()
{
    if (g_signalRaised) {
        m_aborted = true;
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
