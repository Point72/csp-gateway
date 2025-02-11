
const get_openapi = async () => {
    const openapi = await fetch(`${window.location.protocol}//${window.location.host}/openapi.json`);
    return openapi.json();
} 


(async () => {
    const openapi = await get_openapi();
    document.title = openapi.info.title;
})()
