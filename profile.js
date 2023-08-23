document.getElementById("profile-picture-input").addEventListener("change", function(event) {
    const profilePicture = document.getElementById("profile-picture");
    profilePicture.src = URL.createObjectURL(event.target.files[0]);
  });
