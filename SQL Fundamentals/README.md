# SQL Fundamentals (ENG ver)

This is a comprehensive summary of the **SQL (Structured Query Language)** concepts and commands essential for working with relational databases, forming a critical foundation for web application security (Web Hacking).

## 1. 📊 Core Database Concepts (Databases 101)

|**Concept**|**Description**|
|---|---|
|**SQL vs NoSQL**|**SQL (Relational)** stores structured data in tables (rows/columns), ideal for data requiring high accuracy (e.g., transactions).<br><br>  <br><br>**NoSQL** stores flexible data (e.g., JSON), ideal for varied data (e.g., social media).|
|**Table**|The primary container for data, like a "file cabinet" (e.g., `Books` table).|
|**Columns**|The "attributes" or "categories" of data to be stored (e.g., `id`, `name`, `price`).|
|**Rows**|A single "record" or "entry" of data within a table.|
|**Primary Key (PK)**|A column with a **Unique** value (e.g., `id`) used to identify that specific row.|
|**Foreign Key (FK)**|A column that **Links** to the Primary Key of another table, creating a relationship.|

---

## 2. ⚙️ Initial Setup & Structure Commands

**Task 3** introduces **SQL** as the "language" used to command a **DBMS** (Database Management System, e.g., `MySQL`).

**Task 4** covers the basic commands for creating the database schema (structure).

### Database Management

```
-- Create a new database
CREATE DATABASE thm_bookmarket_db;

-- Show all existing databases
SHOW DATABASES;

-- (Important!) Select the database to work with
USE thm_bookmarket_db;

-- Delete a database (if no longer needed)
DROP DATABASE thm_bookmarket_db;
```

### Table Management

```
-- Create a new table (must USE a database first)
CREATE TABLE book_inventory (
    book_id INT AUTO_INCREMENT PRIMARY KEY,
    book_name VARCHAR(255) NOT NULL,
    publication_date DATE
);

-- Show all tables in the currently USE'd database
SHOW TABLES;

-- Describe the structure (columns) of a table
DESCRIBE book_inventory;

-- Alter an existing table (e.g., add a column)
ALTER TABLE book_inventory ADD page_count INT;

-- Delete a table
DROP TABLE book_inventory;
```

---

## 3. ✍️ Data Management (CRUD Operations)

**CRUD** stands for the four basic operations for managing "data" _within_ a table.

|**CRUD**|**SQL Command**|**Example**|
|---|---|---|
|**C**reate|`INSERT INTO`|`INSERT INTO books (id, name) VALUES (1, "New Book");`|
|**R**ead|`SELECT`|`SELECT * FROM books;` (Select all columns)<br><br>  <br><br>`SELECT name, description FROM books;` (Select specific columns)|
|**U**pdate|`UPDATE ... SET`|`UPDATE books SET name = "Updated Name" WHERE id = 1;`|
|**D**elete|`DELETE FROM`|`DELETE FROM books WHERE id = 1;`|

> **⚠️ Warning:** `UPDATE` and `DELETE` statements **must always** have a `WHERE` clause! Otherwise, they will affect _every row_ in the table.

---

## 4. 🔍 Filtering & Sorting (Clauses & Operators)

We use Clauses and Operators to "filter" and "sort" the results from a `SELECT` query.

### Clauses

|**Clause**|**Function**|
|---|---|
|**`DISTINCT`**|Returns only "unique" (non-duplicate) values.|
|**`GROUP BY`**|"Groups" rows that have the same values (often used with `COUNT`, `SUM`).|
|**`ORDER BY ... ASC/DESC`**|"Sorts" the results (ASC = Ascending, DESC = Descending).|
|**`HAVING`**|"Filters" data _after_ it has been grouped by `GROUP BY`.|

### Operators

|**Operator**|**Function**|
|---|---|
|**`LIKE '%text%'`**|Searches for a text "pattern" (`%` = any character(s)).|
|**`AND` / `OR` / `NOT`**|Logical operators.|
|**`BETWEEN ... AND ...`**|Selects values "within" a given range.|
|**`=` / `!=` / `>` / `<` / `>=` / `<=`**|Comparison operators (Equal, Not Equal, Greater Than, etc.).|

---

## 5. 🛠️ Functions (Functions)

Functions help us "manipulate" or "summarize" data directly in our queries.

### String Functions

|**Function**|**Function**|
|---|---|
|**`CONCAT(str1, str2)`**|"Concatenates" (joins) two or more strings.|
|**`GROUP_CONCAT(col)`**|(Powerful) "Joins" strings from multiple rows into a single string (used with `GROUP BY`).|
|**`SUBSTRING(col, start, len)`**|"Extracts" a substring (start at `start`, get `len` characters).|
|**`LENGTH(col)`**|"Counts the length" of a string.|

### Aggregate Functions

|**Function**|**Function**|
|---|---|
|**`COUNT(*)`**|"Counts" the total number of rows.|
|**`SUM(col)`**|Calculates the "sum" of a numeric column.|
|**`MAX(col)`**|Finds the "maximum" value.|
|*_`MIN(col)`_|Finds the "minimum" value.|
