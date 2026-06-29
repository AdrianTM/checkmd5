#include "checkmd5.h"
#include "version.h"
#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    // Set application information
    app.setApplicationName("checkmd5-qt");
    app.setApplicationVersion(CHECKMD5_VERSION);
    app.setOrganizationName("MX Linux");

    // Create and run the main application
    CheckMD5 checker;
    ExitCode result = checker.run(app.arguments());

    return static_cast<int>(result);
}
