<?php
// Include database connection
require_once 'db.php';
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
// Set the Content-Type header to JSON
header('Content-Type: application/json');

// Handle incoming POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? json_decode(file_get_contents('php://input'), true)['action'];

    switch ($action) {
        case 'signup':
            handleSignup($db);
            break;
        case 'login':
            handleLogin($db);
            break;
        case 'search':
            handleSearch($db);
            break;
        case 'send_message':
            handleSendMessage($db);
            break;
        case 'fetch_messages':
            handleFetchMessages($db);
            break;
        case 'fetch_notifications':
            handleFetchNotifications($db);
            break;
        case 'mark_notifications_read':
            handleMarkNotificationsRead($db);
            break;
       case 'typing_status': // Added case for typing status
            handleTypingStatus($db);
            break;
        case 'get_typing_status': // Added case for fetching typing status
            handleGetTypingStatus($db);
            break;
    case 'create_group':
        createGroup($db);
        break;

    case 'fetch_public_groups':
    fetchPublicGroups($db); // Pass database connection
    break;
case 'fetch_user_groups':
    fetchUserGroups($db);
    break;

        default:
            echo json_encode(['success' => false, 'message' => 'Invalid action']);
    }
}

// Handle user signup
function handleSignup($db) {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT); // Encrypt password
    $profileIcon = $_FILES['profile_icon']['name'];

    $targetDir = "uploads/";
    $targetFile = $targetDir . basename($profileIcon);

    if (!move_uploaded_file($_FILES['profile_icon']['tmp_name'], $targetFile)) {
        echo json_encode(['success' => false, 'message' => 'Failed to upload profile icon']);
        return;
    }

    try {
        $stmt = $db->prepare("INSERT INTO users (username, password, profile_icon, last_active) VALUES (?, ?, ?, NOW())");
        $stmt->execute([$username, $password, $targetFile]);
        echo json_encode(['success' => true, 'message' => 'Signup successful']);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Username already exists']);
    }
}

// Handle user login
function handleLogin($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'];
    $password = $data['password'];

    try {
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // Update last active timestamp
            $stmt = $db->prepare("UPDATE users SET last_active = NOW() WHERE id = ?");
            $stmt->execute([$user['id']]);

            echo json_encode(['success' => true, 'message' => 'Login successful', 'user_id' => $user['id'], 'username' => $user['username'], 'profile_icon' => $user['profile_icon']]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Login failed: ' . $e->getMessage()]);
    }
}

// Handle user search
function handleSearch($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'];

    try {
        $stmt = $db->prepare("
            SELECT id, username, profile_icon, 
                   TIMESTAMPDIFF(MINUTE, last_active, NOW()) AS inactive_minutes 
            FROM users 
            WHERE username = ?
        ");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $isOnline = $user['inactive_minutes'] <= 5;

            echo json_encode([
                'success' => true,
                'username' => $user['username'],
                'profile_icon' => $user['profile_icon'],
                'id' => $user['id'],
                'is_online' => $isOnline
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'User not found']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Search failed: ' . $e->getMessage()]);
    }
}

// Handle sending messages
function handleSendMessage($db) {
    $senderId = $_POST['sender_id'];
    $receiverId = $_POST['receiver_id'];
    $message = $_POST['message'] ?? null;

    $attachment = null; // Initialize attachment variable
    if (!empty($_FILES['attachment']['name'])) {
        // Allowed file types
        $allowedExtensions = ['jpg', 'png', 'pdf', 'gif', 'mp4', 'mp3'];
        $fileExtension = strtolower(pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION));

        if (in_array($fileExtension, $allowedExtensions)) {
            $uploadDir = "uploads/private/"; // Directory for uploaded files
            $filePath = $uploadDir . uniqid() . "_" . basename($_FILES['attachment']['name']);

            // Move uploaded file to the server directory
            if (move_uploaded_file($_FILES['attachment']['tmp_name'], $filePath)) {
                $attachment = $filePath; // Set the attachment path
            } else {
                echo json_encode(['success' => false, 'message' => 'Failed to upload attachment']);
                return;
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid file type']);
            return;
        }
    }

    try {
        // Insert the message into the database
        $stmt = $db->prepare("INSERT INTO messages (sender_id, receiver_id, message, attachment) VALUES (?, ?, ?, ?)");
        $stmt->execute([$senderId, $receiverId, $message, $attachment]);

        // Add a notification for the receiver
        $stmt = $db->prepare("INSERT INTO notifications (sender_id, receiver_id, message) VALUES (?, ?, ?)");
        $stmt->execute([$senderId, $receiverId, $message]);

        echo json_encode(['success' => true, 'message' => 'Message sent successfully']);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to send message: ' . $e->getMessage()]);
    }
}

// Handle fetching messages
function handleFetchMessages($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    $userId = $data['user_id'];
    $friendId = $data['friend_id'];

    try {
        // Get sender and receiver profile details
        $stmt = $db->prepare("SELECT username, profile_icon FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $currentUser = $stmt->fetch(PDO::FETCH_ASSOC);

        $stmt = $db->prepare("SELECT username, profile_icon FROM users WHERE id = ?");
        $stmt->execute([$friendId]);
        $friend = $stmt->fetch(PDO::FETCH_ASSOC);

        // Fetch messages between the two users
        $stmt = $db->prepare("
            SELECT sender_id, message, attachment, timestamp 
            FROM messages 
            WHERE (sender_id = ? AND receiver_id = ?) 
               OR (sender_id = ? AND receiver_id = ?) 
            ORDER BY timestamp ASC
        ");
        $stmt->execute([$userId, $friendId, $friendId, $userId]);
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode([
            'success' => true,
            'currentUser' => $currentUser,
            'friend' => $friend,
            'messages' => $messages
        ]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to fetch messages: ' . $e->getMessage()]);
    }
}

// Handle fetching notifications
function handleFetchNotifications($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    $userId = $data['user_id'];

    try {
        $stmt = $db->prepare("
            SELECT n.sender_id, u.username, u.profile_icon, n.message 
            FROM notifications n
            JOIN users u ON n.sender_id = u.id
            WHERE n.receiver_id = ? AND n.is_read = 0
            ORDER BY n.created_at DESC
        ");
        $stmt->execute([$userId]);
        $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode(['success' => true, 'notifications' => $notifications]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to fetch notifications: ' . $e->getMessage()]);
    }
}

// Handle marking notifications as read
function handleMarkNotificationsRead($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    $userId = $data['user_id'];
    $friendId = $data['friend_id'];

    try {
        $stmt = $db->prepare("
            UPDATE notifications 
            SET is_read = 1 
            WHERE receiver_id = ? AND sender_id = ?
        ");
        $stmt->execute([$userId, $friendId]);

        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to mark notifications as read: ' . $e->getMessage()]);
    }
}
function handleTypingStatus($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    $senderId = $data['sender_id'];
    $receiverId = $data['receiver_id'];
    $isTyping = $data['is_typing'];

    try {
        // Check if typing status already exists
        $stmt = $db->prepare("SELECT * FROM typing_status WHERE sender_id = ? AND receiver_id = ?");
        $stmt->execute([$senderId, $receiverId]);
        $existingRecord = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existingRecord) {
            // Update the existing typing status
            $stmt = $db->prepare("UPDATE typing_status SET is_typing = ?, updated_at = NOW() WHERE sender_id = ? AND receiver_id = ?");
            $stmt->execute([$isTyping, $senderId, $receiverId]);
        } else {
            // Insert a new typing status record
            $stmt = $db->prepare("INSERT INTO typing_status (sender_id, receiver_id, is_typing, updated_at) VALUES (?, ?, ?, NOW())");
            $stmt->execute([$senderId, $receiverId, $isTyping]);
        }

        echo json_encode(['success' => true, 'message' => 'Typing status updated']);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to update typing status: ' . $e->getMessage()]);
    }
}
function handleGetTypingStatus($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    $userId = $data['user_id'];
    $friendId = $data['friend_id'];

    try {
        $stmt = $db->prepare("
            SELECT ts.is_typing, u.username 
            FROM typing_status ts
            JOIN users u ON ts.sender_id = u.id
            WHERE ts.sender_id = ? AND ts.receiver_id = ?
        ");
        $stmt->execute([$friendId, $userId]);
        $typingStatus = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($typingStatus) {
            echo json_encode([
                'success' => true,
                'is_typing' => $typingStatus['is_typing'],
                'username' => $typingStatus['username'] // Ensure username is included
            ]);
        } else {
            echo json_encode(['success' => true, 'is_typing' => false]);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to fetch typing status: ' . $e->getMessage()]);
    }
}
function createGroup($db) {
    // Validate required inputs
    if (empty($_POST['group_name']) || empty($_POST['group_privacy'])) {
        echo json_encode(['success' => false, 'message' => 'Group name and privacy are required']);
        exit;
    }

    $groupName = htmlspecialchars($_POST['group_name']);
    $groupDescription = htmlspecialchars($_POST['group_description'] ?? '');
    $groupPrivacy = $_POST['group_privacy'];
    $createdBy = $_POST['user_id']; // Validate user ID

    if (empty($createdBy)) {
        echo json_encode(['success' => false, 'message' => 'User ID is required.']);
        exit;
    }

    $groupIconPath = null;

    // Handle group icon upload if provided
    if (!empty($_FILES['group_icon']['name'])) {
        $uploadDir = 'uploads/groups/';
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true); // Create directory if it doesn't exist
        }

        $iconName = time() . '_' . basename($_FILES['group_icon']['name']); // Unique file name
        $groupIconPath = $uploadDir . $iconName;
        if (!move_uploaded_file($_FILES['group_icon']['tmp_name'], $groupIconPath)) {
            echo json_encode(['success' => false, 'message' => 'Failed to upload group icon']);
            exit;
        }
    }

    // Insert group into database
    try {
        $stmt = $db->prepare("INSERT INTO groups (name, description, privacy, icon, created_by) VALUES (?, ?, ?, ?, ?)");
        if ($stmt->execute([$groupName, $groupDescription, $groupPrivacy, $groupIconPath, $createdBy])) {
            echo json_encode(['success' => true, 'message' => 'Group created successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to create group']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
    exit;
}

function fetchPublicGroups($db) {
    // Check if database connection exists
    if (!$db) {
        echo json_encode(['success' => false, 'message' => 'Database connection not established.']);
        exit;
    }

    try {
        // SQL Query to fetch only public groups and their creators
        $query = "
            SELECT 
                g.name AS group_name, 
                g.icon AS group_icon, 
                g.description AS group_description, 
                u.username AS creator_username, 
                u.profile_icon AS creator_icon
            FROM groups g
            JOIN users u ON g.created_by = u.id
            WHERE g.privacy = 'public' -- Only public groups
            ORDER BY g.created_at DESC";

        // Prepare the query
        $stmt = $db->prepare($query);

        // Execute the query
        $stmt->execute();

        // Check if query execution was successful
        if (!$stmt) {
            echo json_encode(['success' => false, 'message' => 'Query execution failed.']);
            exit;
        }

        // Process query results using PDO fetch method
        $groups = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) { // Use PDO fetch method
            $groups[] = $row;
        }

        // Return groups or empty message
        if (empty($groups)) {
            echo json_encode(['success' => false, 'message' => 'No public groups found.']);
        } else {
            echo json_encode(['success' => true, 'groups' => $groups]);
        }
    } catch (Exception $e) {
        // Handle unexpected errors
        echo json_encode(['success' => false, 'message' => 'An error occurred.', 'error' => $e->getMessage()]);
    }
}

function fetchUserGroups($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    $userId = $data['user_id'] ?? null;

    if (!$userId) {
        echo json_encode(['success' => false, 'message' => 'User ID is required']);
        return;
    }

    try {
        $stmt = $db->prepare("SELECT id, name, description, icon, privacy, created_at 
                              FROM groups 
                              WHERE created_by = ?");
        $stmt->execute([$userId]);
        $groups = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($groups) {
            echo json_encode(['success' => true, 'groups' => $groups]);
        } else {
            echo json_encode(['success' => false, 'message' => 'No groups found']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Failed to fetch user groups: ' . $e->getMessage()]);
    }
}
?>
	