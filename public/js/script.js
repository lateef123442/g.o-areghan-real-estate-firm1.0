(() => {

  // Render listings paged
  function renderListings(listingsToRender, page = 1) {
    const grid = document.getElementById('listings-grid');
    grid.innerHTML = '';
    const startIdx = (page - 1) * listingsPerPage;
    const endIdx = startIdx + listingsPerPage;
    const pageItems = listingsToRender.slice(startIdx, endIdx);
    if (pageItems.length === 0) {
      grid.innerHTML = '<p>No listings found matching your criteria.</p>';
      return;
    }
    pageItems.forEach(p => {
      grid.appendChild(buildPropertyCard(p));
    });
  }
  // Filter listings by search parameters
  function filterListings() {
    const location = document.getElementById('search-location').value.trim().toLowerCase();
    const minPrice = parseInt(document.getElementById('search-min-price').value) || 0;
    const maxPrice = parseInt(document.getElementById('search-max-price').value) || Infinity;
    const minBeds = parseInt(document.getElementById('search-min-bedrooms').value) || 0;
    const minBaths = parseInt(document.getElementById('search-min-baths').value) || 0;

    filteredListings = listings.filter(p => {
      const matchesLocation = location === '' || p.address.toLowerCase().includes(location) || p.title.toLowerCase().includes(location);
      const matchesMinPrice = p.price >= minPrice;
      const matchesMaxPrice = p.price <= maxPrice;
      const matchesBeds = p.bedrooms >= minBeds;
      const matchesBaths = p.bathrooms >= minBaths;
      return matchesLocation && matchesMinPrice && matchesMaxPrice && matchesBeds && matchesBaths;
    });
    currentPage = 1;
    renderListings(filteredListings, currentPage);
    updatePagination();
    if (filteredListings.length === 0) {
      showToast('No properties matched your search criteria', { icon: 'error', duration: 5000 });
    } else {
      showToast(filteredListings.length + ' properties found', { icon: 'check_circle', duration: 3000 });
    }
  }
  // Pagination controls
  function updatePagination() {
    document.getElementById('prev-page').disabled = currentPage === 1;
    document.getElementById('next-page').disabled = currentPage * listingsPerPage >= filteredListings.length;
  }
  function goToPreviousPage() {
    if (currentPage > 1) {
      currentPage--;
      renderListings(filteredListings, currentPage);
      updatePagination();
      scrollToTopListings();
    }
  }
  function goToNextPage() {
    if (currentPage * listingsPerPage < filteredListings.length) {
      currentPage++;
      renderListings(filteredListings, currentPage);
      updatePagination();
      scrollToTopListings();
    }
  }
  function scrollToTopListings() {
    document.getElementById('listings-grid').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Sidebar toggle for mobile
  const sidebar = document.querySelector('.sidebar');
  const sidebarToggleBtn = document.querySelector('.sidebar-toggle-btn');
  if (sidebar && sidebarToggleBtn) {
    sidebarToggleBtn.addEventListener('click', () => {
      const expanded = sidebarToggleBtn.getAttribute('aria-expanded') === 'true';
      sidebarToggleBtn.setAttribute('aria-expanded', (!expanded).toString());
      sidebar.classList.toggle('open');
    });

    // Close sidebar if click outside on mobile
    document.body.addEventListener('click', e => {
      if (
        sidebar.classList.contains('open') &&
        !sidebar.contains(e.target) &&
        !sidebarToggleBtn.contains(e.target)
      ) {
        sidebar.classList.remove('open');
        sidebarToggleBtn.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // Header user icon buttons (simulate notifications)
  const notificationsBtn = document.querySelector('.header-right > button[aria-label="Notifications"]');
  if (notificationsBtn) {
    notificationsBtn.addEventListener('click', () => {
      showToast('You have 4 new alerts', { icon: 'notifications', duration: 4000 });
    });
  }

  const profileBtn = document.querySelector('.header-right > button[aria-label="User profile menu"]');
  if (profileBtn) {
    profileBtn.addEventListener('click', () => {
      showToast('User profile menu opened', { icon: 'person', duration: 3000 });
    });
  }

  // Search submit button with validation
  const searchBtn = document.getElementById('search-submit');
  const locationInput = document.getElementById('search-location');
  if (searchBtn && locationInput) {
    searchBtn.addEventListener('click', e => {
      e.preventDefault();
      // Basic validation: location required
      const locationVal = locationInput.value.trim();
      if (locationVal.length < 3) {
        showToast('Please enter at least 3 characters in Location', { icon: 'error', duration: 4000 });
        locationInput.focus();
        return;
      }
      filterListings();
    });

    // Keyboard navigation enhancement and submit by enter on location input
    locationInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        searchBtn.click();
      }
    });
  }

  // Keyboard shortcuts for pagination
  document.addEventListener('keydown', e => {
    if (e.target.tagName.match(/INPUT|SELECT|TEXTAREA/i)) return;
    if (e.key === 'ArrowRight' || (e.key === 'PageDown')) {
      goToNextPage();
    } else if (e.key === 'ArrowLeft' || (e.key === 'PageUp')) {
      goToPreviousPage();
    }
  });

  // Pagination buttons
  const prevPageBtn = document.getElementById('prev-page');
  const nextPageBtn = document.getElementById('next-page');
  if (prevPageBtn && nextPageBtn) {
    prevPageBtn.addEventListener('click', goToPreviousPage);
    nextPageBtn.addEventListener('click', goToNextPage);
  }
  
  // Accessibility enhancements: focus outline visible for keyboard users only
  function handleFirstTab(e) {
    if (e.key === 'Tab') {
      document.body.classList.add('user-is-tabbing');
      window.removeEventListener('keydown', handleFirstTab);
    }
  }
  window.addEventListener('keydown', handleFirstTab);

  // Admin dropdown toggle
  const dropdownToggle = document.querySelector('.dropdown-toggle');
  const adminMenu = document.getElementById('admin-menu');
  if (dropdownToggle && adminMenu) {
    dropdownToggle.addEventListener('click', function() {
      const expanded = this.getAttribute('aria-expanded') === 'true';
      this.setAttribute('aria-expanded', !expanded);
      adminMenu.classList.toggle('show');
    });
  }

    // Like / Save helpers (exposed globally)
    window.toggleLike = async function(propertyId, btn) {
      try {
        btn.disabled = true;
        const res = await fetch('/property/like', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ propertyId }) });
        const j = await res.json();
        if (!res.ok) throw new Error(j.error || 'Failed');
        const countSpan = document.querySelector(`#like-count-${propertyId}`);
        if (countSpan) countSpan.textContent = j.likes || 0;
        if (j.liked) btn.classList.add('liked'); else btn.classList.remove('liked');
      } catch (err) {
        console.error('Like error', err);
        alert('Could not like property. Please try again.');
      } finally { btn.disabled = false; }
    };

    window.toggleSave = async function(propertyId, btn) {
      try {
        btn.disabled = true;
        const res = await fetch('/property/save', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ propertyId }) });
        const j = await res.json();
        if (!res.ok) throw new Error(j.error || 'Failed');
        const countSpan = document.querySelector(`#save-count-${propertyId}`);
        if (countSpan) countSpan.textContent = j.saves || 0;
        if (j.saved) btn.classList.add('saved'); else btn.classList.remove('saved');
      } catch (err) {
        console.error('Save error', err);
        alert('Could not save property. Please try again.');
      } finally { btn.disabled = false; }
    };

})();

