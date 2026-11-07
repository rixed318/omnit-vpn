#include "include/ui/setting/dialog_omnit_services.h"

#include "include/configs/OmnitServiceRouting.hpp"
#include "include/database/RoutesRepo.h"
#include "include/global/Configs.hpp"

#include <QApplication>
#include <QDialogButtonBox>
#include <QFrame>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPainter>
#include <QPushButton>
#include <QScrollArea>
#include <QSet>
#include <QVBoxLayout>

OmnitRoutingSwitch::OmnitRoutingSwitch(QWidget* parent) : QAbstractButton(parent) {
    setCheckable(true);
    setCursor(Qt::PointingHandCursor);
    setFocusPolicy(Qt::StrongFocus);
    setAccessibleName(tr("VPN routing switch"));
}

QSize OmnitRoutingSwitch::sizeHint() const {
    return {48, 26};
}

void OmnitRoutingSwitch::paintEvent(QPaintEvent*) {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    const QRectF track(1.0, 2.0, width() - 2.0, height() - 4.0);
    const QColor active(111, 92, 246);
    const QColor inactive = palette().color(QPalette::Mid);
    painter.setPen(Qt::NoPen);
    painter.setBrush(isChecked() ? active : inactive);
    painter.drawRoundedRect(track, track.height() / 2.0, track.height() / 2.0);

    const qreal diameter = track.height() - 6.0;
    const qreal x = isChecked() ? track.right() - diameter - 3.0 : track.left() + 3.0;
    painter.setBrush(Qt::white);
    painter.drawEllipse(QRectF(x, track.top() + 3.0, diameter, diameter));

    if (hasFocus()) {
        QPen pen(active.lighter(125));
        pen.setWidthF(1.5);
        painter.setPen(pen);
        painter.setBrush(Qt::NoBrush);
        painter.drawRoundedRect(rect().adjusted(0, 0, -1, -1), 7, 7);
    }
}

DialogOmnitServices::DialogOmnitServices(QWidget* parent) : QDialog(parent) {
    setWindowTitle(QStringLiteral("OMNIT — сайты и приложения"));
    setMinimumSize(720, 640);
    resize(780, 740);
    setModal(true);

    profile_ = Configs::dataManager->routesRepo->GetRouteProfile(
        Configs::dataManager->settingsRepo->current_route_id);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(24, 22, 24, 20);
    root->setSpacing(14);

    auto* title = new QLabel(QStringLiteral("Сайты и приложения"), this);
    QFont titleFont = title->font();
    titleFont.setPointSize(titleFont.pointSize() + 7);
    titleFont.setBold(true);
    title->setFont(titleFont);
    root->addWidget(title);

    auto* intro = new QLabel(
        QStringLiteral("Выбирай, какие сервисы открывать через выбранный VPN-сервер. "
                       "Весь остальной интернет продолжит использовать твой обычный IP."), this);
    intro->setWordWrap(true);
    intro->setStyleSheet(QStringLiteral("color: palette(mid); font-size: 10.5pt;"));
    root->addWidget(intro);

    auto* statusCard = new QFrame(this);
    statusCard->setObjectName(QStringLiteral("omnitStatusCard"));
    statusCard->setStyleSheet(QStringLiteral(
        "QFrame#omnitStatusCard { background: palette(alternate-base); border: 1px solid palette(midlight); "
        "border-radius: 12px; }"));
    auto* statusLayout = new QHBoxLayout(statusCard);
    statusLayout->setContentsMargins(16, 11, 16, 11);
    auto* statusDot = new QLabel(QStringLiteral("●"), statusCard);
    statusDot->setStyleSheet(QStringLiteral("color: #6f5cf6; font-size: 14pt;"));
    auto* statusText = new QLabel(statusCard);
    if (profile_ && !profile_->isRaw) {
        statusText->setText(QStringLiteral("Профиль: %1   •   Режим по умолчанию: Напрямую")
                                .arg(profile_->name.toHtmlEscaped()));
    } else {
        statusText->setText(QStringLiteral("Текущий профиль не поддерживает простые переключатели"));
    }
    statusLayout->addWidget(statusDot);
    statusLayout->addWidget(statusText, 1);
    root->addWidget(statusCard);

    const auto& catalog = Configs::OmnitServiceCatalog();
    int automaticCount = 0;
    QSet<QString> catalogCategories;
    for (const auto& service : catalog) {
        if (service.broadCategory) {
            ++automaticCount;
        } else {
            catalogCategories.insert(service.category);
        }
    }
    const int serviceCount = catalog.size() - automaticCount;

    auto* catalogSummary = new QLabel(
        QStringLiteral("Каталог загружен: %1 сервисов  •  %2 категории  •  %3 автоправила")
            .arg(serviceCount)
            .arg(catalogCategories.size())
            .arg(automaticCount), this);
    catalogSummary->setStyleSheet(
        QStringLiteral("color: #6f5cf6; font-weight: 600; padding: 2px 4px;"));
    root->addWidget(catalogSummary);

    auto* search = new QLineEdit(this);
    search->setPlaceholderText(
        QStringLiteral("Поиск по %1 сервисам, категории или названию…").arg(serviceCount));
    search->setClearButtonEnabled(true);
    search->setMinimumHeight(38);
    connect(search, &QLineEdit::textChanged, this, &DialogOmnitServices::filterServices);
    root->addWidget(search);

    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* content = new QWidget(scroll);
    auto* servicesLayout = new QVBoxLayout(content);
    servicesLayout->setContentsMargins(0, 0, 8, 0);
    servicesLayout->setSpacing(8);

    const auto choices = Configs::ReadOmnitServiceChoices(profile_);
    QString currentCategory;
    for (const auto& service : catalog) {
        if (service.category != currentCategory) {
            currentCategory = service.category;
            auto* category = new QLabel(currentCategory, content);
            QFont categoryFont = category->font();
            categoryFont.setBold(true);
            categoryFont.setPointSize(categoryFont.pointSize() + 1);
            category->setFont(categoryFont);
            category->setContentsMargins(4, currentCategory.isEmpty() ? 0 : 9, 0, 2);
            categoryLabels_.insert(currentCategory, category);
            servicesLayout->addWidget(category);
        }

        auto* card = new QFrame(content);
        card->setObjectName(QStringLiteral("serviceCard"));
        card->setStyleSheet(QStringLiteral(
            "QFrame#serviceCard { background: palette(base); border: 1px solid palette(midlight); "
            "border-radius: 10px; } QFrame#serviceCard:hover { border-color: #8b7cf7; }"));
        auto* row = new QHBoxLayout(card);
        row->setContentsMargins(15, 11, 14, 11);
        row->setSpacing(14);

        auto* textColumn = new QVBoxLayout();
        textColumn->setSpacing(2);
        auto* serviceTitle = new QLabel(service.title, card);
        QFont serviceFont = serviceTitle->font();
        serviceFont.setBold(true);
        serviceTitle->setFont(serviceFont);
        auto* description = new QLabel(service.description, card);
        description->setStyleSheet(QStringLiteral("color: palette(mid);"));
        description->setWordWrap(true);
        textColumn->addWidget(serviceTitle);
        textColumn->addWidget(description);
        if (service.securitySensitive) {
            auto* warning = new QLabel(QStringLiteral("Чувствительный сервис: проверяй страну и IP"), card);
            warning->setStyleSheet(QStringLiteral("color: #d97706; font-size: 9pt;"));
            textColumn->addWidget(warning);
        }
        row->addLayout(textColumn, 1);

        auto* state = new QLabel(card);
        state->setMinimumWidth(92);
        state->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        auto* toggle = new OmnitRoutingSwitch(card);
        const bool useProxy = choices.value(service.id, service.defaultProxy);
        toggle->setChecked(useProxy);
        toggle->setEnabled(profile_ && !profile_->isRaw);
        toggle->setAccessibleDescription(service.title);
        switches_.insert(service.id, toggle);
        serviceCards_.insert(service.id, card);
        stateLabels_.insert(service.id, state);
        updateStateLabel(service.id, useProxy);
        connect(toggle, &QAbstractButton::toggled, this,
                [this, id = service.id](bool checked) { updateStateLabel(id, checked); });
        row->addWidget(state);
        row->addWidget(toggle);
        servicesLayout->addWidget(card);
    }
    servicesLayout->addStretch();
    scroll->setWidget(content);
    root->addWidget(scroll, 1);

    auto* footer = new QHBoxLayout();
    auto* defaults = new QPushButton(QStringLiteral("Вернуть рекомендуемые"), this);
    defaults->setEnabled(profile_ && !profile_->isRaw);
    connect(defaults, &QPushButton::clicked, this, &DialogOmnitServices::resetDefaults);
    footer->addWidget(defaults);
    footer->addStretch();

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel | QDialogButtonBox::Save, this);
    buttons->button(QDialogButtonBox::Save)->setText(QStringLiteral("Применить"));
    buttons->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("Отмена"));
    buttons->button(QDialogButtonBox::Save)->setEnabled(profile_ && !profile_->isRaw);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, this, &DialogOmnitServices::applyChoices);
    footer->addWidget(buttons);
    root->addLayout(footer);
}

void DialogOmnitServices::filterServices(const QString& text) {
    const auto needle = text.trimmed();
    QHash<QString, bool> visibleCategories;
    for (const auto& service : Configs::OmnitServiceCatalog()) {
        const bool visible = needle.isEmpty() || service.id.contains(needle, Qt::CaseInsensitive) ||
                             service.title.contains(needle, Qt::CaseInsensitive) ||
                             service.description.contains(needle, Qt::CaseInsensitive) ||
                             service.category.contains(needle, Qt::CaseInsensitive);
        if (auto* card = serviceCards_.value(service.id, nullptr)) card->setVisible(visible);
        if (visible) visibleCategories.insert(service.category, true);
    }
    for (auto it = categoryLabels_.cbegin(); it != categoryLabels_.cend(); ++it)
        it.value()->setVisible(visibleCategories.value(it.key(), false));
}

void DialogOmnitServices::updateStateLabel(const QString& id, bool useProxy) {
    auto* label = stateLabels_.value(id, nullptr);
    if (!label) return;
    label->setText(useProxy ? QStringLiteral("Через VPN") : QStringLiteral("Напрямую"));
    label->setStyleSheet(useProxy ? QStringLiteral("color: #6f5cf6; font-weight: 600;")
                                  : QStringLiteral("color: palette(mid);"));
}

void DialogOmnitServices::resetDefaults() {
    for (const auto& service : Configs::OmnitServiceCatalog()) {
        if (auto* toggle = switches_.value(service.id, nullptr))
            toggle->setChecked(service.defaultProxy);
    }
}

void DialogOmnitServices::applyChoices() {
    if (!profile_ || profile_->isRaw) return;
    QHash<QString, bool> choices;
    for (const auto& service : Configs::OmnitServiceCatalog()) {
        if (auto* toggle = switches_.value(service.id, nullptr))
            choices.insert(service.id, toggle->isChecked());
    }
    Configs::ApplyOmnitServiceChoices(profile_, choices);
    if (!Configs::dataManager->routesRepo->Save(profile_)) {
        QMessageBox::warning(this, QStringLiteral("OMNIT"),
                             QStringLiteral("Не удалось сохранить правила маршрутизации."));
        return;
    }
    Configs::dataManager->settingsRepo->active_routing = profile_->name;
    Configs::dataManager->settingsRepo->Save();
    emit routingApplied();
    accept();
}
