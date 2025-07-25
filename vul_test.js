// archivo: vulnerable.js

// Mi variable secreta
const miVar = "<script>alert('XSS en PullBrain');</script>";

// Función que simula inyectar contenido en el DOM
function mostrarContenido() {
    document.getElementById("contenido").innerHTML = miVar;
}

// Llamada a la función (simulando un evento de carga)
window.onload = mostrarContenido;
