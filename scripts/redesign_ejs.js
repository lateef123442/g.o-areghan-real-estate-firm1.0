const fs = require('fs');
const path = require('path');

const viewsDir = path.join(__dirname, '../views');

const replacements = [
  // --- Standardize colors to luxury midnight navy and champagne gold ---
  {
    pattern: /--navy:\s*#0d2137;?\s*--navy-mid:\s*#163352;?\s*--navy-light:\s*#1e4a78;?/gi,
    replacement: '--navy: #0a1128; --navy-mid: #101c3d; --navy-light: #1c2d5a;'
  },
  {
    pattern: /--gold:\s*#c8922a;?\s*--gold-light:\s*#e0aa45;?\s*--gold-pale:\s*#f5e6c8;?/gi,
    replacement: '--gold: #b38a38; --gold-light: #d4af37; --gold-pale: #fcf9f2;'
  },
  {
    pattern: /--cream:\s*#faf7f2;?\s*--white:\s*#ffffff;?/gi,
    replacement: '--cream: #faf9f6; --white: #ffffff;'
  },
  {
    pattern: /--text:\s*#0d1f35;?/gi,
    replacement: '--text: #0a1128;'
  },
  {
    pattern: /--shadow-sm:\s*0\s*1px\s*3px\s*rgba\(13,33,55,0\.08\);?\s*--shadow-md:\s*0\s*4px\s*20px\s*rgba\(13,33,55,0\.10\);?/gi,
    replacement: '--shadow-sm: 0 2px 8px rgba(10, 17, 40, 0.04); --shadow-md: 0 10px 30px rgba(10, 17, 40, 0.06);'
  },
  {
    pattern: /--shadow-lg:\s*0\s*12px\s*50px\s*rgba\(13,33,55,0\.15\);?\s*--shadow-xl:\s*0\s*24px\s*80px\s*rgba\(13,33,55,0\.2\);?/gi,
    replacement: '--shadow-lg: 0 20px 50px -12px rgba(10, 17, 40, 0.12); --shadow-xl: 0 30px 70px -15px rgba(10, 17, 40, 0.18);'
  },

  // --- Single-line formats / Indented formats (like website.ejs) ---
  {
    pattern: /--navy:\s*#0d2137/g,
    replacement: '--navy: #0a1128'
  },
  {
    pattern: /--navy-mid:\s*#163352/g,
    replacement: '--navy-mid: #101c3d'
  },
  {
    pattern: /--navy-light:\s*#1e4a78/g,
    replacement: '--navy-light: #1c2d5a'
  },
  {
    pattern: /--gold:\s*#c8922a/g,
    replacement: '--gold: #b38a38'
  },
  {
    pattern: /--gold-light:\s*#e0aa45/g,
    replacement: '--gold-light: #d4af37'
  },
  {
    pattern: /--gold-pale:\s*#f5e6c8/g,
    replacement: '--gold-pale: #fcf9f2'
  },
  {
    pattern: /--cream:\s*#faf7f2/g,
    replacement: '--cream: #faf9f6'
  },
  {
    pattern: /--text:\s*#0d1f35/g,
    replacement: '--text: #0a1128'
  },
  {
    pattern: /--shadow-sm:\s*0\s*1px\s*3px\s*rgba\(13,\s*33,\s*55,\s*0\.08\)/gi,
    replacement: '--shadow-sm: 0 2px 8px rgba(10, 17, 40, 0.04)'
  },
  {
    pattern: /--shadow-md:\s*0\s*4px\s*20px\s*rgba\(13,\s*33,\s*55,\s*0\.10\)/gi,
    replacement: '--shadow-md: 0 10px 30px rgba(10, 17, 40, 0.06)'
  },
  {
    pattern: /--shadow-lg:\s*0\s*12px\s*50px\s*rgba\(13,\s*33,\s*55,\s*0\.15\)/gi,
    replacement: '--shadow-lg: 0 20px 50px -12px rgba(10, 17, 40, 0.12)'
  },
  {
    pattern: /--shadow-xl:\s*0\s*24px\s*80px\s*rgba\(13,\s*33,\s*55,\s*0\.2\)/gi,
    replacement: '--shadow-xl: 0 30px 70px -15px rgba(10, 17, 40, 0.18)'
  },

  // --- chat.ejs specific inline colors ---
  {
    pattern: /--navy:#0d2137;\s*--navy-mid:#163352;\s*--navy-light:#1e4a78;/gi,
    replacement: '--navy:#0a1128; --navy-mid:#101c3d; --navy-light:#1c2d5a;'
  },
  {
    pattern: /--gold:#c8922a;\s*--gold-light:#e0aa45;/gi,
    replacement: '--gold:#b38a38; --gold-light:#d4af37;'
  },
  {
    pattern: /--cream:#faf7f2;\s*--white:#ffffff;/gi,
    replacement: '--cream:#faf9f6; --white:#ffffff;'
  },
  {
    pattern: /--text:#0d1f35;\s*--online:#22c55e;/gi,
    replacement: '--text:#0a1128; --online:#10b981;'
  },
  {
    pattern: /--shadow-sm:0\s*1px\s*3px\s*rgba\(13,33,55,0\.08\);/gi,
    replacement: '--shadow-sm:0 2px 8px rgba(10, 17, 40, 0.04);'
  },
  {
    pattern: /--shadow-md:0\s*4px\s*20px\s*rgba\(13,33,55,0\.10\);/gi,
    replacement: '--shadow-md:0 10px 30px rgba(10, 17, 40, 0.06);'
  },
  {
    pattern: /--shadow-lg:0\s*12px\s*50px\s*rgba\(13,33,55,0\.15\);/gi,
    replacement: '--shadow-lg:0 20px 50px -12px rgba(10, 17, 40, 0.12);'
  },

  // --- Inject elegant modern fonts and animations system-wide ---
  {
    pattern: /font-family:\s*'DM Sans',/g,
    replacement: "font-family: 'Plus Jakarta Sans', 'DM Sans',"
  },
  {
    pattern: /family=Cormorant\+Garamond:wght@400;500;600;700&family=DM\+Sans:wght@300;400;500;600;700/g,
    replacement: "family=Cormorant+Garamond:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800"
  },
  // Smooth transitions on card hovering
  {
    pattern: /transition:\s*all\s*0\.3s\s*cubic-bezier\(0\.4,\s*0,\s*0\.2,\s*1\);/g,
    replacement: "transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);"
  },
  {
    pattern: /transition:\s*transform\s*0\.3s\s*cubic-bezier\(0\.4,\s*0,\s*0\.2,\s*1\);/g,
    replacement: "transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.4s cubic-bezier(0.16, 1, 0.3, 1);"
  }
];

const targetFiles = [
  'chat.ejs',
  'customer-buy-page.ejs',
  'customer-rent-page.ejs',
  'customer-sell-page.ejs',
  'gallery.ejs',
  'login.ejs',
  'property-valuation.ejs',
  'signin-page.ejs',
  'view-details.ejs',
  'website.ejs'
];

targetFiles.forEach(file => {
  const filePath = path.join(viewsDir, file);
  if (!fs.existsSync(filePath)) {
    console.log(`⚠️ File not found: ${file}`);
    return;
  }

  let content = fs.readFileSync(filePath, 'utf8');
  let originalContent = content;

  replacements.forEach(({ pattern, replacement }) => {
    content = content.replace(pattern, replacement);
  });

  if (content !== originalContent) {
    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`✅ Successfully redesigned ${file}`);
  } else {
    console.log(`ℹ️ No style match in ${file} (already up-to-date)`);
  }
});
console.log('🎉 Design overhaul completed across all client templates!');
