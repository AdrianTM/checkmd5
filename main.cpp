#include "checkmd5.h"
#include "version.h"
#include <QCoreApplication>
#include <QLibraryInfo>
#include <QLocale>
#include <QTranslator>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    // Set application information
    app.setApplicationName("checkmd5-qt");
    app.setApplicationVersion(VERSION);
    app.setOrganizationName("checkmd5");

    // Setup internationalization
    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "checkmd5_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            app.installTranslator(&translator);
            break;
        }
    }

    // Create and run the main application
    CheckMD5 checker;
    ExitCode result = checker.run(app.arguments());

    return static_cast<int>(result);
}
