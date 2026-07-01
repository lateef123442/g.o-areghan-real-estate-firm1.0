const fs = require('fs');
const path = require('path');

const viewsDir = path.join(__dirname, '..', 'views');

function walk(dir) {
  return fs.readdirSync(dir).flatMap(name => {
    const fp = path.join(dir, name);
    if (fs.statSync(fp).isDirectory()) return walk(fp);
    return fp;
  });
}

const files = walk(viewsDir).filter(f => f.endsWith('.ejs') || f.endsWith('.html') || f.endsWith('.js'));
let changed = 0;

files.forEach(file => {
  let content = fs.readFileSync(file, 'utf8');
  const original = content;
  // Replace href="some.html" (not starting with / or http)
  content = content.replace(/href=\"(?!\/|https?:)([^\"]+\.html)\"/g, 'href="/$1"');
  // Also replace action attributes or other forms if needed
  content = content.replace(/action=\"(?!\/|https?:)([^\"]+\.html)\"/g, 'action="/$1"');
  if (content !== original) {
    fs.writeFileSync(file, content, 'utf8');
    changed++;
    console.log('Updated', file);
  }
});
console.log('Files changed:', changed);