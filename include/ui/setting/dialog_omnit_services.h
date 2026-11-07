#pragma once

#include <QAbstractButton>
#include <QDialog>
#include <QHash>

#include <memory>

namespace Configs {
    class RouteProfile;
}

class OmnitRoutingSwitch final : public QAbstractButton {
    Q_OBJECT

public:
    explicit OmnitRoutingSwitch(QWidget* parent = nullptr);
    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;
};

class DialogOmnitServices final : public QDialog {
    Q_OBJECT

public:
    explicit DialogOmnitServices(QWidget* parent = nullptr);

signals:
    void routingApplied();

private:
    std::shared_ptr<Configs::RouteProfile> profile_;
    QHash<QString, OmnitRoutingSwitch*> switches_;
    QHash<QString, class QLabel*> stateLabels_;
    QHash<QString, class QWidget*> serviceCards_;
    QHash<QString, class QLabel*> categoryLabels_;

    void applyChoices();
    void filterServices(const QString& text);
    void resetDefaults();
    void updateStateLabel(const QString& id, bool useProxy);
};
