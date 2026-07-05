const fs = require('fs');
const path = require('path');

const viewsDir = path.join(__dirname, '../views');

const filesToFix = [
  'website.ejs',
  'customer-buy-page.ejs',
  'customer-rent-page.ejs',
  'customer-sell-page.ejs',
  'gallery.ejs',
  'property-valuation.ejs',
  'login.ejs',
  'signin-page.ejs'
];

filesToFix.forEach(file => {
  const filePath = path.join(viewsDir, file);
  if (!fs.existsSync(filePath)) {
    console.log(`⚠️ File not found: ${file}`);
    return;
  }

  let content = fs.readFileSync(filePath, 'utf8');
  let originalContent = content;

  // 1. Replace logo placeholder background url with premium villa image
  content = content.replace(/url\(['"]?\/img\/OGA AYO COM CARDXS\.jpg['"]?\)/gi, "url('/img/luxury_villa_hero.jpg')");

  // 2. Replace screenshot backgrounds in customer-sell-page with premium villa
  content = content.replace(/\/img\/Screenshot_20250927-131850_WhatsAppBusiness\[1\]\.jpg/gi, (match, offset, fullText) => {
    // If it's a CSS background declaration, use the hero image
    const precedingContext = fullText.slice(Math.max(0, offset - 30), offset);
    if (precedingContext.toLowerCase().includes('url(') || precedingContext.toLowerCase().includes('background')) {
      return '/img/luxury_villa_hero.jpg';
    }
    // If it's a logo or image src, use the real company logo
    return '/img/OGA AYO COM CARDXS.jpg';
  });

  // 3. Fix broken logo image link in login.ejs
  content = content.replace(/\/img\/2d4e5309b19b488c9ac5d29f32c6d100\(1\)\.jpg/gi, '/img/OGA AYO COM CARDXS.jpg');

  if (content !== originalContent) {
    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`✅ Fixed media assets in ${file}`);
  } else {
    console.log(`ℹ️ Media assets in ${file} already corrected`);
  }
});
console.log('🎉 Media assets redesign completed successfully!');
