#pragma once
#include <QMainWindow>
#include <QTabWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QTextEdit>
#include <QPushButton>
#include <QFileInfo>
#include <QDir>
#include "KeyManager.h"
#include "Signer.h"
#include "Verifier.h"
#include "HashUtils.h"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override = default;

private slots:
    void onBrowsePrivKeyPath();
    void onBrowsePubKeyPath();
    void onGenerateKeys();
    void onBrowseSignFile();
    void onBrowseSignPrivKey();
    void onBrowseSignSigOut();
    void onSignFile();
    void onBrowseVerifyFile();
    void onBrowseVerifySig();
    void onBrowseVerifyPubKey();
    void onVerifyFile();
    void onBrowseHashFile();
    void onComputeHash();
    void onCopyHash();
    void onBrowseSigViewFile();
    void onViewSig();
    

private:
    KeyManager keyManager_;
    Signer     signer_;
    Verifier   verifier_;

    QTabWidget* tabs_;

    QLineEdit*  privKeyPathEdit_;
    QLineEdit*  pubKeyPathEdit_;
    QComboBox*  keySizeCombo_;
    QLineEdit*  passphraseEdit_;
    QTextEdit*  genLog_;

    QLineEdit*  signFileEdit_;
    QLineEdit*  signPrivKeyEdit_;
    QLineEdit*  signSigOutEdit_;
    QLineEdit*  signPassEdit_;
    QTextEdit*  signLog_;

    QLineEdit*  verifyFileEdit_;
    QLineEdit*  verifySigEdit_;
    QLineEdit*  verifyPubKeyEdit_;
    QTextEdit*  verifyLog_;

    QLineEdit*  hashFileEdit_;
    QLabel*     hashResultLabel_;
    QLabel*     hashFileSizeLabel_;
    QPushButton* hashCopyBtn_;
    QTextEdit*  hashLog_;

    QLineEdit*  sigViewEdit_;
    QTextEdit*  sigViewOutput_;

    

    QWidget* buildKeygenTab();
    QWidget* buildSignTab();
    QWidget* buildVerifyTab();
    QWidget* buildHashTab();
    QWidget* buildSigViewTab();

    void logSuccess(QTextEdit* log, const QString& msg);
    void logError  (QTextEdit* log, const QString& msg);
    void logInfo   (QTextEdit* log, const QString& msg);
    void logWarn   (QTextEdit* log, const QString& msg);
};
