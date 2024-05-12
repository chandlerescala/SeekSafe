use SeekSafe
CREATE VIEW vw_PendingRequest 
AS 
SELECT [itemID]
      ,[userIDNum]
      ,[itemName]
      ,CASE 
            WHEN [itemType] = 1 THEN 'Electronic devices'
            WHEN [itemType] = 2 THEN 'Clothing'
            WHEN [itemType] = 3 THEN 'Jewelry'
            WHEN [itemType] = 4 THEN 'Books'
            WHEN [itemType] = 5 THEN 'Accessories'
            WHEN [itemType] = 6 THEN 'Documents'
            WHEN [itemType] = 7 THEN 'Sporting goods'
            ELSE 'Miscellaneous items'
       END AS [itemType]
      ,[itemDescription]
      ,[ImageUrl]
      ,[locationName]
      ,[date]
	  ,[time]
	FROM Item WHERE itemStatus = 'Found Item'

CREATE PROCEDURE sp_ApproveItem @itemID int
AS
UPDATE Item SET itemStatus = 'Verified'
WHERE itemID = @itemID

CREATE PROCEDURE sp_DeletePendingReports @itemID int
AS
DELETE FROM Item WHERE itemID = @itemID

CREATE PROCEDURE sp_ClaimedItem @itemID int
AS
UPDATE Item SET itemStatus = 'Claimed'
WHERE itemID = @itemID

CREATE PROCEDURE sp_FoundItem @itemID int
AS
UPDATE Item SET itemStatus = 'Found Item'
WHERE itemID = @itemID

CREATE PROCEDURE sp_Verified @itemID int
AS
UPDATE Item SET itemStatus = 'Verified'
WHERE itemID = @itemID

CREATE VIEW vw_VerifiedItems AS
SELECT [itemID]
      ,[userIDNum]
      ,[itemName]
      ,CASE 
            WHEN [itemType] = 1 THEN 'Electronic devices'
            WHEN [itemType] = 2 THEN 'Clothing'
            WHEN [itemType] = 3 THEN 'Jewelry'
            WHEN [itemType] = 4 THEN 'Books'
            WHEN [itemType] = 5 THEN 'Accessories'
            WHEN [itemType] = 6 THEN 'Documents'
            WHEN [itemType] = 7 THEN 'Sporting goods'
            ELSE 'Miscellaneous items'
       END AS [itemType]
      ,[itemDescription]
      ,[ImageUrl]
      ,[locationName]
      ,[date]
	  ,[time]
	FROM Item WHERE itemStatus = 'Verified'

CREATE VIEW vw_ClaimedReports AS
SELECT [itemID]
      ,[userIDNum]
      ,[itemName]
      ,[itemType]
      ,[itemDescription]
      ,[ImageUrl]
      ,[locationName]
      ,[date]
	  ,[time]
	FROM Item WHERE itemStatus = 'Claimed'

CREATE VIEW vw_ToClaimingRequest AS
SELECT [itemID]
      ,[userIDNum]
      ,[itemName]
      ,[itemType]
      ,[itemDescription]
      ,[ImageUrl]
      ,[locationName]
      ,[date]
	  ,[time]
	FROM Item WHERE itemStatus = 'Claiming'


CREATE PROCEDURE sp_DeleteAccount @userID int
AS
DELETE FROM UserAccount WHERE userID = @userID


CREATE VIEW vw_ToClaimingRequest AS
SELECT [itemID],
       [userIDNum],
       [itemName],
       CASE 
            WHEN [itemType] = 1 THEN 'Electronic devices'
            WHEN [itemType] = 2 THEN 'Clothing'
            WHEN [itemType] = 3 THEN 'Jewelry'
            WHEN [itemType] = 4 THEN 'Books'
            WHEN [itemType] = 5 THEN 'Accessories'
            WHEN [itemType] = 6 THEN 'Documents'
            WHEN [itemType] = 7 THEN 'Sporting goods'
            ELSE 'Miscellaneous items'
       END AS [itemType],
       [itemDescription],
       [ImageUrl],
       [locationName],
       [date]
FROM Item 
WHERE itemStatus = 'Claiming';

SELECT * FROM vw_ToClaimingRequest 

DELETE FROM Item WHERE [time] IS NULL;