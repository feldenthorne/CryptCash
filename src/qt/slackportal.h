#ifndef SLACK_H
#define SLACK_H

#include <QWidget>

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QTime>
#include <QTimer>
#include <QStringList>
#include <QMap>
#include <QSettings>
#include <QSlider>

namespace Ui {
class SlackPortal;
}
class ClientModel;

class SlackPortal : public QWidget
{
    Q_OBJECT

public:
    explicit SlackPortal(QWidget *parent = 0);
    ~SlackPortal();
    
    void setModel(ClientModel *model);
    
private:
    Ui::SlackPortal *ui;
    ClientModel *model;
    
};

#endif // BLOCKBROWSER_H
