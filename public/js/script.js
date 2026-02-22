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

  // Header user icon buttons (simulate notifications)
  const notificationsBtn = document.querySelector('.header-right > button[aria-label="Notifications"]');
  notificationsBtn.addEventListener('click', () => {
    showToast('You have 4 new alerts', { icon: 'notifications', duration: 4000 });
  });

  const profileBtn = document.querySelector('.header-right > button[aria-label="User profile menu"]');
  profileBtn.addEventListener('click', () => {
    showToast('User profile menu opened', { icon: 'person', duration: 3000 });
  });

  // Search submit button with validation
  const searchBtn = document.getElementById('search-submit');
  searchBtn.addEventListener('click', e => {
    e.preventDefault();
    // Basic validation: location required
    const locationVal = document.getElementById('search-location').value.trim();
    if (locationVal.length < 3) {
      showToast('Please enter at least 3 characters in Location', { icon: 'error', duration: 4000 });
      document.getElementById('search-location').focus();
      return;
    }
    filterListings();
  });

  // Keyboard navigation enhancement and submit by enter on location input
  const locationInput = document.getElementById('search-location');
  locationInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
    
      searchBtn.click();
    }
  });

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
  document.getElementById('prev-page').addEventListener('click', goToPreviousPage);
  document.getElementById('next-page').addEventListener('click', goToNextPage);

  
  // Accessibility enhancements: focus outline visible for keyboard users only
  function handleFirstTab(e) {
    if (e.key === 'Tab') {
      document.body.classList.add('user-is-tabbing');
      window.removeEventListener('keydown', handleFirstTab);
    }
  }
  window.addEventListener('keydown', handleFirstTab);

     // Admin dropdown toggle
  document.querySelector('.dropdown-toggle').addEventListener('click', function() {
    const expanded = this.getAttribute('aria-expanded') === 'true';
    this.setAttribute('aria-expanded', !expanded);
    document.getElementById('admin-menu').classList.toggle('show');
  });

})();

