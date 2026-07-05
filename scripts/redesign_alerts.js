const fs = require('fs');
const path = require('path');

const viewsDir = path.join(__dirname, '../views');

const alertFiles = [
  { file: 'invalid-email.ejs', isSuccess: false },
  { file: 'invalid-login.ejs', isSuccess: false },
  { file: 'valid-email.ejs', isSuccess: true },
  { file: 'valid-login.ejs', isSuccess: true },
  { file: 'sales-approved-successfully.ejs', isSuccess: true },
  { file: 'sales-declined-successfully.ejs', isSuccess: false },
  { file: 'tour-approved-successfully.ejs', isSuccess: true },
  { file: 'tour-declined-successfully.ejs', isSuccess: false },
  { file: 'tour-submitted.ejs', isSuccess: true }
];

const newStyle = (isSuccess) => `
    /* Full screen overlay */
    .overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background-color: rgba(15, 23, 42, 0.6);
      backdrop-filter: blur(8px);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 10000;
      font-family: 'Plus Jakarta Sans', 'Inter', system-ui, sans-serif;
    }

    /* Alert box centered */
    .alert {
      background-color: #ffffff;
      color: #0f172a;
      padding: 36px 32px;
      border-radius: 16px;
      border-top: 5px solid ${isSuccess ? '#10b981' : '#ef4444'};
      box-shadow: 0 25px 50px -12px rgba(15, 23, 42, 0.25);
      max-width: 400px;
      width: 90%;
      text-align: center;
      animation: fadeInScale 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }

    .alert div {
      font-size: 1.05rem;
      font-weight: 600;
      line-height: 1.5;
      color: #1e293b;
      margin-bottom: 24px;
    }

    /* OK button */
    .alert button.ok-btn {
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #ffffff;
      border: none;
      padding: 12px 40px;
      border-radius: 10px;
      font-weight: 700;
      font-size: 0.95rem;
      cursor: pointer;
      box-shadow: 0 4px 12px rgba(15, 23, 42, 0.15);
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      width: 100%;
    }
    .alert button.ok-btn:hover {
      background: linear-gradient(135deg, #d4af37 0%, #b38a38 100%);
      color: #0f172a;
      transform: translateY(-1px);
      box-shadow: 0 6px 18px rgba(212, 175, 55, 0.3);
    }

    /* Fade and scale in animation */
    @keyframes fadeInScale {
      from {
        opacity: 0;
        transform: scale(0.9);
      }
      to {
        opacity: 1;
        transform: scale(1);
      }
    }

    /* Fade and scale out animation */
    @keyframes fadeOutScale {
      from {
        opacity: 1;
        transform: scale(1);
      }
      to {
        opacity: 0;
        transform: scale(0.9);
      }
    }
`;

alertFiles.forEach(({ file, isSuccess }) => {
  const filePath = path.join(viewsDir, file);
  if (!fs.existsSync(filePath)) {
    console.log(`⚠️ File not found: ${file}`);
    return;
  }

  let content = fs.readFileSync(filePath, 'utf8');

  // Replace style block contents
  const styleStart = content.indexOf('<style>');
  const styleEnd = content.indexOf('</style>');

  if (styleStart !== -1 && styleEnd !== -1) {
    const updatedContent = content.substring(0, styleStart + 7) + newStyle(isSuccess) + content.substring(styleEnd);
    fs.writeFileSync(filePath, updatedContent, 'utf8');
    console.log(`✅ Redesigned alerts inside ${file}`);
  } else {
    console.log(`❌ Could not locate style tags inside ${file}`);
  }
});
console.log('🎉 Alert page style overhaul completed!');
