# Authentication
Authentication using (Spring security +  JWT token 


first create a  user registration using this End point
http://localhost:8080/auth/addNewUser


then once the user is registered. then looking at the database table , copy the JWT signature and paste in HTTP header section.
and then using this Endpoint , you can login to userProfile section
http://localhost:8080/auth/user/userProfile

