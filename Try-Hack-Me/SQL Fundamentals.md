
```yaml
---
date:  2025-09-20
author: Sameer Sani
reason: 0x45
title:   
tags: 
---
```

## DataBase 101

* So Database is collection of organised structured information like username and passwords, posts etc and etc.
* There are two types of databases:
	* **Relational DB**
	* **NON-Relational DB**

* **Relational DB**
	* Here the data is stored in a structured format like data entry consis of user contains - first_name, last_name, email_address, username and password.
	* And if a user wana login a new column would be created as in Rel. DB data is stored in **rows** and **Coloumns**.
	* Here relationships can be made btw two tables as the name says.

* **Non-Relation DB** 
	* Here data is not stored like the above here we store it in a **non-tabular format**, 
	* EX :

```JSON
		
	{
	    _id: ObjectId("4556712cd2b2397ce1b47661"),
	    name: { first: "Thomas", last: "Anderson" },
	    date_of_birth: new Date('Sep 2, 1964'),
	    occupation: [ "The One"],
	    steps_taken : NumberLong(4738947387743977493)
	}
```

* we use relation DB when have to store the data with accuracy and sconsistent format but when the data can be vary in its format, we use non-relational such as Social Media platforms.


## Tables, Rows and Columns

* So all the data is stored in **Tables here**

* EX:-


| id  | Name       | Publish_Date |
| --- | ---------- | ------------ |
| 1   | Fuck Her   | 12-01-1969   |
| 2   | On The Top | 25-02-1869   |
		Books Table

* Here Name is a column and the id 1 whole data is row.
* When we define column we also have to define the data type if datatype is not matched it is rejected.
* The core data types are Strings (a collection of words and characters), Integers (numbers), floats/decimals (numbers with a decimal point) and Times/Dates.

* **Primary And Foreign Keys**
	* Let say we create a another table name author, and we know it has relation with the Books table,A book (stored in the Books table) is written by an author (stored in the Authors table).
	* What if we have to query the book from the Books table and also tell the author from the Author table, So we need Keys
	* There are 2 types of Keys:-
		* **Primary Key**
			* This key ensure that the data collected in a column is unique, so we can identify it in our example its the **id** Column.
		* **Foreign Key**
			* A foreign key its a column in a table that also exsist in another table within the db.
			* so we have a link btw these two tables. In our example we add another column called "**author_id**" that act as foregin key because the author_id in the Books Table is also present as **id** column in the Author Table.
			* And there can be more then one foreign key column in a table.


## SQL

* DataBases are usually controlled by **Database Management System (DBMS)**, Server act as an interface btw end user and the db.
* DBMS is a software program that allows user to retrieve, update and manage the data being stored, for example **MYSQL**,**MongoDB**, **Oracle DB**, **Maria DB**.
* SQL is a programming language that can be used to query,define and manupulate the data storedi n the Relation DB.

* **MySql in practical**
	* We have to login In 
		* **mysql -u username -p**

	* **DataBase Statements**
		* To create a DATABASE
			* **CREATE DATABASE database_name;**
		* To see DataBase
			* **SHOW DATABASES;**
		* To use DataBase
			* **USE database_name**
		* To Remove Database
			* **DROP database database_name**

	* **Table Statements**
		* To create a Table
			* **CREATE TABLE table_name (
			 column1_name  data_type, 
			 column2_name data_type 
			*);**
			* Example
			```sql
			mysql> CREATE TABLE book_inventory (
			    book_id INT AUTO_INCREMENT PRIMARY KEY,
			    book_name VARCHAR(255) NOT NULL,
			    publication_date DATE);
			```

			* In the above example we have keywords like
				* **AUTO_INCREMENT** :- inc of id would be there
				* **PRIMARY KEY** :- Its the primary key column and has to be unique for each row.
				* **VARCHAR(255)** :- it can use variable char and limit of 255 char.
				* **NOT NULL** :- Can not set null value
				* **DATE** :- Date data type
					
		* To show tables
			* **SHOW TABLES;**

		* **Describe**
			* We we wana know what column are in the table we can use the **DESCRIBE** keyword
				* **DESCRIBE book_inventory**
		* **ALTER**
			* WHEN need for the dataset changes
				* **ALTER TABLE book_inventory**
			* After that add what you wana add
				* ADD page_count INT NOT  NULL

		* **DROP**
			* You can drop tables too 
				* **DROP TABLE table_name**

## CRUD

* Crud stand for **Create, Read, Update** and **Delete** 

* **Create Operation (INSERT)**

	* We can create new records in a table, using statement **INSERT INTO Tablename**
		* EX;- 
		* INSERT INTO books (id, name, published_date, description)
	    VALUES (1, "Android Security Internals", "2014-10-14", "An In-Depth Guide to Android's Security Architecture");
	* We can see it taked a tabel, where you can add a record, like here a new **Column**. **id**, **name**, **published_date**, and **description** are record in the table.

* **Read Operation (SELECT)**
	* We can select any thing from the table
		* SELECT * FROM tablename;
		* SELECT name,description FROM books;

* ***Update Operation (UPDATE)
	* **Update** operation modifies an existing record within a table
		* UPDATE books
		    SET description = "An In-Depth Guide to Android's Security Architecture."
		    WHERE id = 1;
	* We use SET and WHere to specify the area.

* **Delete Operation (DELETE)**
	* The **delete** operation removes records from a table. We can achieve this with the `DELETE` statement.
		* DELETE FROM books WHERE id = 1;

- **Create (INSERT statement)** - Adds a new record to the table.
- **Read (SELECT statement)** - Retrieves record from the table.
- **Update (UPDATE statement)** - Modifies existing data in the table.
- **Delete (DELETE statement)** - Removes record from the table.

## Clause

* It is a part of statement that specifies the criteria of the data being manipulated, usually by initial statement, we use FROM and WHERE which are clause and tell which record should be used.

* **DISTINCT Clause**
	* It is used to avoid duplicate records when doing a query, return only unique values
		* SELECT DISTINCT name FROM books;

* **GROUP BY Clause**
	* It Collect data from multiple reocord and group the query result in columns
		* SELECT name, COUNT() FROM books GROUP BY name
			* Here we use COUNT Function.

* ***ORDER BY Clause***
	* It is used to sort the record, return query in acending or decending order, Using FUC like ASC or DESC
		* SELECT * FROM books ORDER BY published_date ASC.

* **HAVING Clause**
	* It is used with other clauses to filter froups or result on the basic condition, l
			* SELECT name, COUNT(*)
			    FROM books
			    GROUP BY name
			    HAVING name LIKE '%Hack%';

##  Operations

* **Logical Operations**
	* These operation test the truth of the condition anf return a boolean value of TRUE or False.

	* **LIKE**
		* It is used with the **WHERE** clause to filter specific format.
			* **SELECT * FROM books Where discription LIKE "%guide%"**

	 * **AND**
		 * When we have to use multiple condition and return true if both are true
			 * **SELECT * FROM books WHERE category = "This" AND name = "that" ;**

	*  **OR**
		* When we have to use multiple condition and return true if one of them is true.
			* SELECT * FROM books WHERE name LIKE %this% OR name LIKE %that%

	* **NOT** 
		* It reverses the value of a boolean operator.
			* **SELECT * FROM books WHERE NOT Description LIKE %this%**

	* **BETWEEN**
		* It allow us ti test if a value exsist in the defined range.
			* **SELECT * FROM books WHERE id BETWEEN 1 AND 3 *


* **Comparison Operators**
	* The comparison op.erators are used to compare values and check if they meet specified criteria.

	* **Equal to**
		* The `=` (Equal) operator compares two expressions and determines
		* Give Eamples.

	* MENTION ALL THE COMPARISION OPERATOR WITH EXAMPLES IN CODE SNIPPET

## Function

* ***String Functions***

	* **CONCAT**
		* This function is used to add two or more strings together.
			* SELECT CONCAT(name, " is a type of ", category, " book.") AS book_info FROM books;

	* Write about Substring, length with snippets

* **Aggregate Function**
	* Write about count, sum, max, min functions