University Management System

So basically I built a full university management system from scratch. 
It's a web app that handles pretty much everything a university needs 
— students, teachers, courses, grades, attendance, you name it.


Why I built this

I wanted to build something that actually means something, not just 
a random to-do app. A university has so much going on and managing 
it all manually is a nightmare. So I thought — why not build a system 
that puts everything in one place and actually works?


How it works

There are three portals:


Admin Portal

The admin is basically in charge of everything. They can log in and 
add, edit, and delete students and teachers, create and manage courses 
and departments, allocate teachers to courses, enroll students, set up 
timetables and semesters, configure grade boundaries, view analytics 
and manage the whole system.


Teacher Portal

Teachers can sign up and log in to their own dashboard. Once they're 
in they can take attendance, upload grades for midterms, finals, and 
assignments, post assignments with deadlines, share study materials, 
and make announcements for their class.


Student Portal

Students can sign up and log in too. Everything the admin and teacher 
uploads — the student can see it. That includes their enrolled courses, 
timetable, attendance record, grades, assignments, materials, and 
announcements from teachers.


What I built it with

Node.js and Express.js for the backend, MySQL for the database, JWT 
so each user has their own secure login, Bcrypt so passwords are never 
stored as plain text, and HTML, CSS, JavaScript for the frontend.


Security

Every portal has its own separate login token so a student can never 
access teacher or admin data and vice versa. Passwords are fully 
encrypted and all routes are protected.


About me

I'm Areeba and I built this whole thing myself.
GitHub: https://github.com/areeba07-ops
