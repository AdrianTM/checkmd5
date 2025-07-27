#pragma once

#include <QByteArray>
#include <QFileInfo>
#include <QObject>
#include <QStringList>
#include <QTextStream>
#include <memory>

enum class ExitCode : int { Ok = 0, BadCheck = 1, Aborted = 2, BadList = 3, System = 4 };

struct CheckTarget {
    qint64 size;
    QString hash;
    QString path;
};

class CheckMD5 : public QObject
{
    Q_OBJECT

public:
    explicit CheckMD5(QObject* parent = nullptr);

    ExitCode run(const QStringList& arguments);

signals:
    void finished(ExitCode result);
    void progressUpdated(float percentage);
    void statusMessage(const QString& message);

private:
    ExitCode checkFiles(const QList<CheckTarget>& targets);
    QList<CheckTarget> loadTargets(const QStringList& sumFiles);
    bool checkForAbort();
    void logMessage(bool console, const QString& message);
    void updateProgress(qint64 processed, qint64 total);

    // Options
    QString m_logFile;
    bool m_force = false;
    bool m_machine = false;
    bool m_verbose = false;

    // State
    qint64 m_nextProgressUpdate = 0;
    QTextStream* m_logStream = nullptr;
    volatile bool m_aborted = false;
};
