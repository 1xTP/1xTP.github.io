document.addEventListener('DOMContentLoaded', () => {
  const menuToggle = document.querySelector('.menu-toggle');
  const sidebar = document.querySelector('.sidebar');

  if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', () => {
      sidebar.classList.toggle('is-open');
    });
  }
});


const searchInput = document.getElementById('ctfSearch');
  const ctfCards = document.querySelectorAll('.ctf-card');

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const term = e.target.value.toLowerCase();
      ctfCards.forEach(card => card.style.display = card.innerText.toLowerCase().includes(term) ? 'flex' : 'none');
    });
  }