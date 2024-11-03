document.addEventListener('DOMContentLoaded', ()=>{

    const allButtons = document.querySelectorAll('.searchBtn');
    const searchBar = document.querySelector('.searchBar');
    const searchInput = document.getElementById('searchInput');

    const openSearchBar = () => {
        searchBar.style.visibility = 'visible';
        searchBar.classList.add('open');
        searchInput.focus();
    };

    const closeSearchBar = () => {
        searchBar.classList.remove('open');
        setTimeout(() => {
            searchBar.style.visibility = 'hidden'; 
        }, 300); 
    };

    allButtons.forEach(button => {
        button.addEventListener('click', (event) => {
            console.log('Search button clicked');
            event.stopPropagation(); 
            openSearchBar();
        });
    });

    document.addEventListener('click', (event) => {
        if (!searchBar.contains(event.target) && !Array.from(allButtons).some(button => button.contains(event.target))) {
            closeSearchBar();
        }
    });

    searchBar.addEventListener('click', (event) => {
        event.stopPropagation(); 
    });
});

// Get the form elements
const loginBtn = document.getElementById('loginBtn');
const registerBtn = document.getElementById('registerBtn');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');

// Toggle between login and register
loginBtn.addEventListener('click', () => {
    loginForm.classList.add('active');
    registerForm.classList.remove('active');
    loginBtn.classList.add('active');
    registerBtn.classList.remove('active');
});

registerBtn.addEventListener('click', () => {
    registerForm.classList.add('active');
    loginForm.classList.remove('active');
    registerBtn.classList.add('active');
    loginBtn.classList.remove('active');
});