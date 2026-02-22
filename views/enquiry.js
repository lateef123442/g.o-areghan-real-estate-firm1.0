<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Enquiries - G.O AREGBAN REAL ESTATE FIRM</title>
  <!-- Google Material Icons -->
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet" />
  <link rel="stylesheet" href="/css/styles.css">
  <style>
    /* Enquiry Styles (Adapted from Chat) */
    .enquiry-container {
      display: flex;
      height: 80vh;
      background: #f0f0f0;
      border-radius: 15px;
      overflow: hidden;
    }
    .enquiry-list {
      width: 30%;
      background: white;
      border-right: 1px solid #e1e8ed;
      overflow-y: auto;
    }
    .enquiry-list-item {
      display: flex;
      align-items: center;
      padding: 1rem;
      border-bottom: 1px solid #e1e8ed;
      cursor: pointer;
      transition: background 0.3s;
    }
    .enquiry-list-item:hover {
      background: #f8f9fa;
    }
    .enquiry-list-item.active {
      background: #e3f2fd;
    }
    .person-icon {
      margin-right: 1rem;
      color: #3498db;
    }
    .enquiry-window {
      flex: 1;
      display: flex;
      flex-direction: column;
    }
    .enquiry-header {
      background: #3498db;
      color: white;
      padding: 1rem;
      font-weight: 600;
    }
    .enquiry-details {
      flex: 1;
      padding: 1rem;
      background: #f9f9f9;
      overflow-y: auto;
    }
    .enquiry-reply {
      padding: 1rem;
      background: white;
      border-top: 1px solid #e1e8ed;
    }
    .enquiry-reply textarea {
      width: 100%;
      padding: 0.75rem;
      border: 1px solid #e1e8ed;
      border-radius: 8px;
      margin-bottom: 0.5rem;
    }
    .enquiry-reply button {
      padding: 0.75rem 1rem;
      background: #3498db;
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      margin-right: 0.5rem;
    }
    .hidden { display: none; }
  </style>
</head>
<body>
  <div id="app" role="application">
    <!-- Sidebar (Simplified) -->
    <aside class="sidebar" aria-label="Main navigation">
      <nav aria-label="Primary navigation">
        <a href="/submit-listing" tabindex="0" aria-label="Submit Listing">
          <span class="material-icons" aria-hidden="true">add_circle</span>Submit Listing
        </a>
        <a href="/manage-listings" tabindex="0" aria-label="Manage Listings">
          <span class="material-icons" aria-hidden="true">edit</span>Manage Listings
        </a>
        <a href="/inquiries" tabindex="0" aria-label="Inquiries" class="active">
          <span class="material-icons" aria-hidden="true">question_answer</span>Inquiries
        </a>
        <a href="/chat" tabindex="0" aria-label="Client Chat">
          <span class="material-icons" aria-hidden="true">chat</span>Client Chat
        </a>
      </nav>
      <footer>&copy; 2025 G.O AREGBAN REAL ESTATE FIRM. All rights reserved.</footer>
    </aside>

    <header role="banner" aria-label="Primary header">
      <div class="header-left">
        <button class="sidebar-toggle-btn material-icons" aria-label="Toggle navigation menu">menu</button>
        <a href="#" class="logo" aria-label="G.O AREGBAN REAL ESTATE FIRM Home">
          <span class="material-icons" aria-hidden="true">apartment</span>G.O AREGBAN REAL ESTATE FIRM And Consultant
        </a>
      </div>
    </header>

    <main role="main" aria-label="Enquiries">
      <section class="dashboard-section">
        <h1>Enquiries</h1>
        <div class="enquiry-container">
          <div class="enquiry-list">
            <% enquiries.forEach(enquiry => { %>
              <div class="enquiry-list-item" data-enquiry-id="<%= enquiry.id %>">
                <span class="material-icons person-icon">person</span>
                <div>
                  <strong><%= enquiry.name %></strong>
                  <p><%= enquiry.subject || 'General Enquiry' %> - <%= new Date(enquiry.timestamp).toLocaleDateString() %></p>
                </div>
              </div>
            <% }); %>
          </div>
          <div class="enquiry-window hidden" id="enquiry-window">
            <div class="enquiry-header" id="enquiry-header">Select an enquiry</div>
            <div class="enquiry-details" id="enquiry-details"></div>
            <div class="enquiry-reply">
              <textarea id="reply-message" placeholder="Type your reply..."></textarea>
              <button id="reply-btn">Reply</button>
              <button id="resolve-btn">Mark as Resolved</button>
            </div>
          </div>
        </div>
      </section>
    </main>
  </div>

  <script>
    let currentEnquiryId = null;
    let currentEnquiryEmail = null;

    // Load enquiry when clicking a list item
    document.querySelectorAll('.enquiry-list-item').forEach(item => {
      item.addEventListener('click', () => {
        document.querySelectorAll('.enquiry-list-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');
        currentEnquiryId = item.dataset.enquiryId;
        document.getElementById('enquiry-window').classList.remove('hidden');
        // Find the enquiry data (assuming it's passed in EJS)
        const enquiry = <%- JSON.stringify(enquiries) %>.find(e => e.id == currentEnquiryId);
        if (enquiry) {
          currentEnquiryEmail = enquiry.email;
          document.getElementById('enquiry-header').textContent = `Enquiry from ${enquiry.name}`;
          document.getElementById('enquiry-details').innerHTML = `
            <p><strong>Name:</strong> ${enquiry.name}</p>
            <p><strong>Email:</strong> ${enquiry.email}</p>
            <p><strong>Phone:</strong> ${enquiry.phone || 'N/A'}</p>
            <p><strong>Subject:</strong> ${enquiry.subject || 'N/A'}</p>
            <p><strong>Message:</strong> ${enquiry.message}</p>
            <p><strong>Date:</strong> ${new Date(enquiry.timestamp).toLocaleString()}</p>
          `;
        }
      });
    });

    // Reply to enquiry
    document.getElementById('reply-btn').addEventListener('click', () => {
      const replyMessage = document.getElementById('reply-message').value.trim();
      if (replyMessage && currentEnquiryEmail) {
        fetch('/reply-enquiry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: currentEnquiryEmail, message: replyMessage })
        })
        .then(res => res.json())
        .then(data => {
          alert(data.message);
          document.getElementById('reply-message').value = '';
        })
        .catch(err => alert('Error sending reply'));
      } else {
        alert('Please enter a reply message.');
      }
    });

    // Mark as resolved
    document.getElementById('resolve-btn').addEventListener('click', () => {
      if (currentEnquiryId) {
        fetch('/resolve-enquiry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: currentEnquiryId })
        })
        .then(res => res.json())
        .then(data => {
          alert(data.message);
          location.reload();  // Refresh to update list
        })
        .catch(err => alert('Error resolving enquiry'));
      }
    });
  </script>
</body>
</html>