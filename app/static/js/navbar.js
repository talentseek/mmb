window.onscroll = function () {
    var navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.classList.add('sticky-navbar');
    } else {
        navbar.classList.remove('sticky-navbar');
    }
};
