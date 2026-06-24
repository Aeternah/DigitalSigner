#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QDateTime>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QFont>
#include <fstream>
#include <iomanip>
#include <sstream>

// ─────────────────────────────────────────────────────────
// Логирование
// ─────────────────────────────────────────────────────────

void MainWindow::logSuccess(QTextEdit* log, const QString& msg) {
    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
    log->append(QString("<span style='color:#a6e3a1'>[%1] ✔ %2</span>").arg(ts, msg));
}
void MainWindow::logError(QTextEdit* log, const QString& msg) {
    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
    log->append(QString("<span style='color:#f38ba8'>[%1] ✘ %2</span>").arg(ts, msg));
}
void MainWindow::logInfo(QTextEdit* log, const QString& msg) {
    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
    log->append(QString("<span style='color:#89b4fa'>[%1] ℹ %2</span>").arg(ts, msg));
}
void MainWindow::logWarn(QTextEdit* log, const QString& msg) {
    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
    log->append(QString("<span style='color:#f9e2af'>[%1] ⚠ %2</span>").arg(ts, msg));
}

// ─────────────────────────────────────────────────────────
// Конструктор
// ─────────────────────────────────────────────────────────

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      signer_(keyManager_),
      verifier_(keyManager_)
{
    setWindowTitle("Digital Signer v2 — RSA/SHA-256 утилита цифровой подписи");
    setMinimumSize(780, 620);
    resize(860, 680);

    tabs_ = new QTabWidget(this);
    tabs_->addTab(buildKeygenTab(),  " Генерация ключей");
    tabs_->addTab(buildSignTab(),    "Подпись файла");
    tabs_->addTab(buildVerifyTab(),  "Проверка подписи");
    tabs_->addTab(buildHashTab(),    "SHA-256 хеш");
    tabs_->addTab(buildSigViewTab(), " Просмотр .sig");

    setCentralWidget(tabs_);

    setStyleSheet(R"(
        QMainWindow, QWidget { background-color: #1e1e2e; color: #cdd6f4; font-size: 13px; }
        QTabWidget::pane { border: 1px solid #45475a; }
        QTabBar::tab {
            background: #313244; color: #cdd6f4;
            padding: 7px 14px; margin-right: 2px;
            border-radius: 4px 4px 0 0; font-size: 12px;
        }
        QTabBar::tab:selected { background: #89b4fa; color: #1e1e2e; font-weight: bold; }
        QLineEdit, QComboBox, QTextEdit {
            background: #313244; border: 1px solid #45475a;
            border-radius: 4px; padding: 4px 6px; color: #cdd6f4;
        }
        QLineEdit:focus { border-color: #89b4fa; }
        QPushButton {
            background: #89b4fa; color: #1e1e2e;
            border: none; border-radius: 4px;
            padding: 6px 14px; font-weight: bold;
        }
        QPushButton:hover { background: #b4befe; }
        QPushButton:pressed { background: #74c7ec; }
        QPushButton#browseBtn {
            background: #45475a; color: #cdd6f4; padding: 5px 10px;
        }
        QPushButton#browseBtn:hover { background: #585b70; }
        QPushButton#dangerBtn {
            background: #f38ba8; color: #1e1e2e;
        }
        QPushButton#dangerBtn:hover { background: #eba0ac; }
        QGroupBox {
            border: 1px solid #45475a; border-radius: 6px;
            margin-top: 10px; padding: 8px;
            font-weight: bold; color: #89b4fa;
        }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; }
        QLabel { color: #a6adc8; }
        QLabel#hashResult {
            color: #a6e3a1; font-family: monospace; font-size: 12px;
            background: #313244; border: 1px solid #45475a;
            border-radius: 4px; padding: 8px; word-break: break-all;
        }
    )");
}

// ─────────────────────────────────────────────────────────
// Хелпер: строка «поле + кнопка-папка»
// ─────────────────────────────────────────────────────────
static QWidget* makeRow(QLineEdit*& edit, const QString& ph, QObject* receiver, const char* slot) {
    QWidget* w = new QWidget;
    QHBoxLayout* h = new QHBoxLayout(w);
    h->setContentsMargins(0,0,0,0); h->setSpacing(4);
    edit = new QLineEdit; edit->setPlaceholderText(ph);
    QPushButton* btn = new QPushButton("📂"); btn->setObjectName("browseBtn"); btn->setFixedWidth(34);
    QObject::connect(btn, SIGNAL(clicked()), receiver, slot);
    h->addWidget(edit); h->addWidget(btn);
    return w;
}

// ─────────────────────────────────────────────────────────
// ВКЛАДКА 1: Генерация ключей
// ─────────────────────────────────────────────────────────
QWidget* MainWindow::buildKeygenTab() {
    QWidget* w = new QWidget; QVBoxLayout* v = new QVBoxLayout(w); v->setSpacing(10);

    QGroupBox* p = new QGroupBox("Параметры"); QFormLayout* f = new QFormLayout(p); f->setSpacing(8);
    keySizeCombo_ = new QComboBox;
    keySizeCombo_->addItem("RSA-2048 (рекомендуется)", 2048);
    keySizeCombo_->addItem("RSA-3072", 3072);
    keySizeCombo_->addItem("RSA-4096 (максимальная безопасность)", 4096);
    f->addRow("Размер ключа:", keySizeCombo_);
    passphraseEdit_ = new QLineEdit; passphraseEdit_->setEchoMode(QLineEdit::Password);
    passphraseEdit_->setPlaceholderText("Пароль защиты приватного ключа (необязательно)");
    f->addRow("Пароль:", passphraseEdit_);
    v->addWidget(p);

    QGroupBox* paths = new QGroupBox("Пути"); QFormLayout* fp = new QFormLayout(paths); fp->setSpacing(8);
    fp->addRow("Приватный ключ:", makeRow(privKeyPathEdit_, "~/private.pem", this, SLOT(onBrowsePrivKeyPath())));
    fp->addRow("Публичный ключ:", makeRow(pubKeyPathEdit_,  "~/public.pem",  this, SLOT(onBrowsePubKeyPath())));
    v->addWidget(paths);

    privKeyPathEdit_->setText(QDir::homePath() + "/private.pem");
    pubKeyPathEdit_->setText(QDir::homePath() + "/public.pem");

    QPushButton* btn = new QPushButton("Сгенерировать ключевую пару");
    btn->setMinimumHeight(38);
    connect(btn, SIGNAL(clicked()), this, SLOT(onGenerateKeys()));
    v->addWidget(btn);

    genLog_ = new QTextEdit; genLog_->setReadOnly(true); genLog_->setMaximumHeight(140);
    v->addWidget(genLog_); v->addStretch();
    return w;
}

// ─────────────────────────────────────────────────────────
// ВКЛАДКА 2: Подпись файла
// ─────────────────────────────────────────────────────────
QWidget* MainWindow::buildSignTab() {
    QWidget* w = new QWidget; QVBoxLayout* v = new QVBoxLayout(w); v->setSpacing(10);
    QGroupBox* g = new QGroupBox("Параметры подписи"); QFormLayout* f = new QFormLayout(g); f->setSpacing(8);
    f->addRow("Файл:",           makeRow(signFileEdit_,   "Выберите файл для подписи...",   this, SLOT(onBrowseSignFile())));
    f->addRow("Приватный ключ:", makeRow(signPrivKeyEdit_, "Путь к private.pem...",         this, SLOT(onBrowseSignPrivKey())));
    f->addRow("Файл подписи:",   makeRow(signSigOutEdit_,  "Куда сохранить .sig файл...",   this, SLOT(onBrowseSignSigOut())));
    signPassEdit_ = new QLineEdit; signPassEdit_->setEchoMode(QLineEdit::Password);
    signPassEdit_->setPlaceholderText("Пароль к приватному ключу (если есть)");
    f->addRow("Пароль:", signPassEdit_);
    v->addWidget(g);

    QPushButton* btn = new QPushButton("Подписать файл");
    btn->setMinimumHeight(38); connect(btn, SIGNAL(clicked()), this, SLOT(onSignFile()));
    v->addWidget(btn);
    signLog_ = new QTextEdit; signLog_->setReadOnly(true); signLog_->setMaximumHeight(160);
    v->addWidget(signLog_); v->addStretch();
    return w;
}

// ─────────────────────────────────────────────────────────
// ВКЛАДКА 3: Проверка подписи
// ─────────────────────────────────────────────────────────
QWidget* MainWindow::buildVerifyTab() {
    QWidget* w = new QWidget; QVBoxLayout* v = new QVBoxLayout(w); v->setSpacing(10);
    QGroupBox* g = new QGroupBox("Параметры проверки"); QFormLayout* f = new QFormLayout(g); f->setSpacing(8);
    f->addRow("Исходный файл:",  makeRow(verifyFileEdit_,  "Файл, чью подпись проверяем...", this, SLOT(onBrowseVerifyFile())));
    f->addRow("Файл подписи:",   makeRow(verifySigEdit_,   "Путь к .sig файлу...",           this, SLOT(onBrowseVerifySig())));
    f->addRow("Публичный ключ:", makeRow(verifyPubKeyEdit_, "Путь к public.pem...",           this, SLOT(onBrowseVerifyPubKey())));
    v->addWidget(g);

    QPushButton* btn = new QPushButton("Проверить подпись");
    btn->setMinimumHeight(38); connect(btn, SIGNAL(clicked()), this, SLOT(onVerifyFile()));
    v->addWidget(btn);
    verifyLog_ = new QTextEdit; verifyLog_->setReadOnly(true); verifyLog_->setMaximumHeight(160);
    v->addWidget(verifyLog_); v->addStretch();
    return w;
}

// ─────────────────────────────────────────────────────────
// ВКЛАДКА 4: SHA-256 хеш
// ─────────────────────────────────────────────────────────
QWidget* MainWindow::buildHashTab() {
    QWidget* w = new QWidget; QVBoxLayout* v = new QVBoxLayout(w); v->setSpacing(10);

    QGroupBox* g = new QGroupBox("Вычислить SHA-256 хеш файла");
    QVBoxLayout* gl = new QVBoxLayout(g);

    QWidget* row = makeRow(hashFileEdit_, "Выберите любой файл...", this, SLOT(onBrowseHashFile()));
    gl->addWidget(row);

    QPushButton* computeBtn = new QPushButton("Вычислить SHA-256");
    computeBtn->setMinimumHeight(36);
    connect(computeBtn, SIGNAL(clicked()), this, SLOT(onComputeHash()));
    gl->addWidget(computeBtn);

    v->addWidget(g);

    // Результат
    QGroupBox* res = new QGroupBox("Результат");
    QVBoxLayout* rl = new QVBoxLayout(res);

    hashFileSizeLabel_ = new QLabel("Размер файла: —");
    rl->addWidget(hashFileSizeLabel_);

    hashResultLabel_ = new QLabel("SHA-256: —");
    hashResultLabel_->setObjectName("hashResult");
    hashResultLabel_->setWordWrap(true);
    hashResultLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rl->addWidget(hashResultLabel_);

    hashCopyBtn_ = new QPushButton("Скопировать хеш");
    hashCopyBtn_->setEnabled(false);
    connect(hashCopyBtn_, SIGNAL(clicked()), this, SLOT(onCopyHash()));
    rl->addWidget(hashCopyBtn_);
    v->addWidget(res);

    hashLog_ = new QTextEdit; hashLog_->setReadOnly(true); hashLog_->setMaximumHeight(130);
    v->addWidget(hashLog_);

    QGroupBox* note = new QGroupBox("Что это такое?");
    QLabel* info = new QLabel(
        "SHA-256 — детерминированная хеш-функция. Любое изменение файла\n"
        "(даже одного бита) полностью меняет хеш. Именно хеш шифруется\n"
        "приватным ключом RSA — это и есть цифровая подпись."
    );
    info->setStyleSheet("color: #a6adc8; font-size: 12px;");
    info->setWordWrap(true);
    QVBoxLayout* nl = new QVBoxLayout(note); nl->addWidget(info);
    v->addWidget(note);
    v->addStretch();
    return w;
}

// ─────────────────────────────────────────────────────────
// ВКЛАДКА 5: Просмотр .sig файла
// ─────────────────────────────────────────────────────────
QWidget* MainWindow::buildSigViewTab() {
    QWidget* w = new QWidget; QVBoxLayout* v = new QVBoxLayout(w); v->setSpacing(10);

    QGroupBox* g = new QGroupBox("Открыть и просмотреть .sig файл");
    QVBoxLayout* gl = new QVBoxLayout(g);
    gl->addWidget(makeRow(sigViewEdit_, "Выберите .sig файл...", this, SLOT(onBrowseSigViewFile())));

    QPushButton* btn = new QPushButton("Показать содержимое");
    btn->setMinimumHeight(36);
    connect(btn, SIGNAL(clicked()), this, SLOT(onViewSig()));
    gl->addWidget(btn);
    v->addWidget(g);

    sigViewOutput_ = new QTextEdit;
    sigViewOutput_->setReadOnly(true);
    sigViewOutput_->setFont(QFont("Monospace", 10));
    v->addWidget(sigViewOutput_);

    QLabel* note = new QLabel(
        "ℹ  .sig файл — это бинарный файл, содержащий RSA-подпись (зашифрованный хеш).\n"
        "Он не является зашифрованным документом. Исходный файл остаётся открытым."
    );
    note->setStyleSheet("color: #a6adc8; font-size: 12px;");
    note->setWordWrap(true);
    v->addWidget(note);
    v->addStretch();
    return w;
}



// ─────────────────────────────────────────────────────────
// Слоты: Генерация ключей
// ─────────────────────────────────────────────────────────
void MainWindow::onBrowsePrivKeyPath() {
    QString f = QFileDialog::getSaveFileName(this, "Приватный ключ", QDir::homePath(), "PEM (*.pem)");
    if (!f.isEmpty()) privKeyPathEdit_->setText(f);
}
void MainWindow::onBrowsePubKeyPath() {
    QString f = QFileDialog::getSaveFileName(this, "Публичный ключ", QDir::homePath(), "PEM (*.pem)");
    if (!f.isEmpty()) pubKeyPathEdit_->setText(f);
}
void MainWindow::onGenerateKeys() {
    QString priv = privKeyPathEdit_->text().trimmed();
    QString pub  = pubKeyPathEdit_->text().trimmed();
    if (priv.isEmpty() || pub.isEmpty()) { logError(genLog_, "Укажите пути"); return; }
    int bits = keySizeCombo_->currentData().toInt();
    KeyManager::KeySize ks = (bits == 4096) ? KeyManager::KeySize::RSA_4096 :
                             (bits == 3072) ? KeyManager::KeySize::RSA_3072 :
                                              KeyManager::KeySize::RSA_2048;
    logInfo(genLog_, QString("Генерация RSA-%1... (может занять несколько секунд)").arg(bits));
    if (keyManager_.generateRSAKeyPair(priv.toStdString(), pub.toStdString(), ks,
                                        passphraseEdit_->text().toStdString())) {
        logSuccess(genLog_, "Ключевая пара создана!");
        logInfo(genLog_, "Приватный: " + priv);
        logInfo(genLog_, "Публичный: " + pub);
        signPrivKeyEdit_->setText(priv);
        verifyPubKeyEdit_->setText(pub);
    } else {
        logError(genLog_, QString::fromStdString(keyManager_.lastError()));
    }
}

// ─────────────────────────────────────────────────────────
// Слоты: Подпись
// ─────────────────────────────────────────────────────────
void MainWindow::onBrowseSignFile() {
    QString f = QFileDialog::getOpenFileName(this, "Выбрать файл", QDir::homePath());
    if (!f.isEmpty()) {
        signFileEdit_->setText(f);
        if (signSigOutEdit_->text().isEmpty()) signSigOutEdit_->setText(f + ".sig");
    }
}
void MainWindow::onBrowseSignPrivKey() {
    QString f = QFileDialog::getOpenFileName(this, "Приватный ключ", QDir::homePath(), "PEM (*.pem);;Все (*)");
    if (!f.isEmpty()) signPrivKeyEdit_->setText(f);
}
void MainWindow::onBrowseSignSigOut() {
    QString f = QFileDialog::getSaveFileName(this, "Сохранить подпись", QDir::homePath(), "Signature (*.sig)");
    if (!f.isEmpty()) signSigOutEdit_->setText(f);
}
void MainWindow::onSignFile() {
    if (signFileEdit_->text().isEmpty() || signPrivKeyEdit_->text().isEmpty() || signSigOutEdit_->text().isEmpty()) {
        logError(signLog_, "Заполните все поля"); return;
    }
    QString file = signFileEdit_->text().trimmed();
    logInfo(signLog_, "Вычисляем SHA-256 и создаём подпись...");
    QString hashBefore = QString::fromStdString(HashUtils::sha256File(file.toStdString()));
    if (signer_.signFile(file.toStdString(), signPrivKeyEdit_->text().toStdString(),
                         signSigOutEdit_->text().toStdString(), signPassEdit_->text().toStdString())) {
        logSuccess(signLog_, "Файл подписан!");
        logInfo(signLog_, "SHA-256 файла: " + hashBefore);
        logInfo(signLog_, "Подпись: " + signSigOutEdit_->text());
        long sz = HashUtils::fileSize(signSigOutEdit_->text().toStdString());
        logInfo(signLog_, QString("Размер .sig файла: %1 байт").arg(sz));
        verifyFileEdit_->setText(file);
        verifySigEdit_->setText(signSigOutEdit_->text());
    } else {
        logError(signLog_, QString::fromStdString(signer_.lastError()));
    }
}

// ─────────────────────────────────────────────────────────
// Слоты: Проверка
// ─────────────────────────────────────────────────────────
void MainWindow::onBrowseVerifyFile() {
    QString f = QFileDialog::getOpenFileName(this, "Исходный файл", QDir::homePath());
    if (!f.isEmpty()) verifyFileEdit_->setText(f);
}
void MainWindow::onBrowseVerifySig() {
    QString f = QFileDialog::getOpenFileName(this, "Файл подписи", QDir::homePath(), "Signature (*.sig);;Все (*)");
    if (!f.isEmpty()) verifySigEdit_->setText(f);
}
void MainWindow::onBrowseVerifyPubKey() {
    QString f = QFileDialog::getOpenFileName(this, "Публичный ключ", QDir::homePath(), "PEM (*.pem);;Все (*)");
    if (!f.isEmpty()) verifyPubKeyEdit_->setText(f);
}
void MainWindow::onVerifyFile() {
    if (verifyFileEdit_->text().isEmpty() || verifySigEdit_->text().isEmpty() || verifyPubKeyEdit_->text().isEmpty()) {
        logError(verifyLog_, "Заполните все поля"); return;
    }
    QString file = verifyFileEdit_->text().trimmed();
    QString hashNow = QString::fromStdString(HashUtils::sha256File(file.toStdString()));
    logInfo(verifyLog_, "SHA-256 файла сейчас: " + hashNow);
    if (verifier_.verifyFile(file.toStdString(), verifySigEdit_->text().toStdString(),
                              verifyPubKeyEdit_->text().toStdString())) {
        logSuccess(verifyLog_, "ПОДПИСЬ ДЕЙСТВИТЕЛЬНА — файл не изменялся");
    } else {
        logError(verifyLog_, "ПОДПИСЬ НЕДЕЙСТВИТЕЛЬНА — " + QString::fromStdString(verifier_.lastError()));
    }
}

// ─────────────────────────────────────────────────────────
// Слоты: SHA-256 хеш
// ─────────────────────────────────────────────────────────
void MainWindow::onBrowseHashFile() {
    QString f = QFileDialog::getOpenFileName(this, "Выбрать файл", QDir::homePath());
    if (!f.isEmpty()) hashFileEdit_->setText(f);
}
void MainWindow::onComputeHash() {
    QString path = hashFileEdit_->text().trimmed();
    if (path.isEmpty()) { logError(hashLog_, "Выберите файл"); return; }
    long sz = HashUtils::fileSize(path.toStdString());
    QString hash = QString::fromStdString(HashUtils::sha256File(path.toStdString()));
    if (hash.isEmpty()) { logError(hashLog_, "Ошибка: " + QString::fromStdString(HashUtils::lastError)); return; }
    hashFileSizeLabel_->setText(QString("Размер файла: %1 байт (%2 КБ)").arg(sz).arg(sz/1024.0, 0, 'f', 1));
    hashResultLabel_->setText("SHA-256:\n" + hash);
    hashCopyBtn_->setEnabled(true);
    logSuccess(hashLog_, "Хеш вычислен для: " + QFileInfo(path).fileName());
    logInfo(hashLog_, hash);
}
void MainWindow::onCopyHash() {
    QString text = hashResultLabel_->text();
    text.remove("SHA-256:\n");
    QApplication::clipboard()->setText(text.trimmed());
    logInfo(hashLog_, "Хеш скопирован в буфер обмена");
}

// ─────────────────────────────────────────────────────────
// Слоты: Просмотр .sig
// ─────────────────────────────────────────────────────────
void MainWindow::onBrowseSigViewFile() {
    QString f = QFileDialog::getOpenFileName(this, "Файл подписи", QDir::homePath(), "Signature (*.sig);;Все (*)");
    if (!f.isEmpty()) sigViewEdit_->setText(f);
}
void MainWindow::onViewSig() {
    QString path = sigViewEdit_->text().trimmed();
    if (path.isEmpty()) { sigViewOutput_->setText("Выберите .sig файл"); return; }

    std::ifstream f(path.toStdString(), std::ios::binary);
    if (!f.is_open()) { sigViewOutput_->setText("Не удалось открыть файл"); return; }
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(f)), {});
    f.close();

    // Hex-дамп
    std::ostringstream hex, ascii;
    QString out;
    out += QString("Файл: %1\nРазмер: %2 байт\n\n").arg(QFileInfo(path).fileName()).arg(bytes.size());
    out += "SHA-256 (хеш подписи):\n";
    out += QString::fromStdString(HashUtils::sha256Bytes(bytes.data(), bytes.size())) + "\n\n";
    out += "HEX-ДАМП (первые 256 байт):\n";
    out += "Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII\n";
    out += QString(70, '-') + "\n";

    size_t limit = std::min(bytes.size(), (size_t)256);
    for (size_t i = 0; i < limit; i += 16) {
        QString line = QString("%1  ").arg(i, 8, 16, QChar('0')).toUpper();
        QString asc;
        for (size_t j = i; j < std::min(i+16, limit); ++j) {
            line += QString("%1 ").arg((unsigned char)bytes[j], 2, 16, QChar('0')).toUpper();
            asc += (bytes[j] >= 32 && bytes[j] < 127) ? QChar(bytes[j]) : QChar('.');
        }
        // padding
        for (size_t j = limit; j < i+16 && limit < i+16; ++j) line += "   ";
        line += " " + asc;
        out += line + "\n";
    }
    if (bytes.size() > 256) out += QString("\n... (%1 байт не показано)").arg(bytes.size() - 256);

    sigViewOutput_->setPlainText(out);
}

