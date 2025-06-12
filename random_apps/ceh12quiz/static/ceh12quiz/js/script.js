// Global variables
let originalQuizData = [];  // Original unmodified quiz data
let quizData = [];          // Working quiz data (may be shuffled)
let currentQuestionId = null;
let answeredQuestions = new Set();
let correctAnswers = 0;
let currentPage = 1;
const questionsPerPage = 20;
let isAutoNextEnabled = false;
let isAutoAnswerEnabled = false;
let isShuffleEnabled = false;
const autoAnswerDelay = 2000; // 2 seconds before showing the correct answer

// Function to get URL query parameters
function getQueryParam(param) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(param);
}

// Function to update URL with current question ID
function updateURLWithQuestionId(questionId) {
    if (!questionId) return;
    
    const url = new URL(window.location);
    url.searchParams.set('id', questionId);
    window.history.replaceState({}, '', url);
}

// DOM Elements
const questionsList = document.getElementById('questions-list');
const questionDisplay = document.getElementById('question-display');
const answersContainer = document.getElementById('answers-container');
const scoreElement = document.getElementById('score');
const totalElement = document.getElementById('total');
const prevPageBtn = document.getElementById('prev-page');
const nextPageBtn = document.getElementById('next-page');
const pageInfoElement = document.getElementById('page-info');
const prevQuestionBtn = document.getElementById('prev-question');
const nextQuestionBtn = document.getElementById('next-question');
const autoNextToggle = document.getElementById('auto-next');
const autoAnswerToggle = document.getElementById('auto-answer');
const shuffleToggle = document.getElementById('shuffle');
const resetProgressBtn = document.getElementById('reset-progress');

// Load quiz data from the questions.js file
function loadQuizData() {
    originalQuizData = JSON.parse(JSON.stringify(quizQuestions)); // Deep copy
    quizData = JSON.parse(JSON.stringify(quizQuestions)); // Start with a copy of the original data
    
    // Initialize the UI
    updateTotalQuestions();
    renderQuestionsList();
}

// Fisher-Yates shuffle algorithm for randomizing questions
function shuffleQuestions() {
    // Create a copy of the original data
    quizData = JSON.parse(JSON.stringify(originalQuizData));
    
    // Shuffle the copy
    for (let i = quizData.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [quizData[i], quizData[j]] = [quizData[j], quizData[i]];
    }
}

// Update total questions count
function updateTotalQuestions() {
    totalElement.textContent = quizData.length;
    // Make sure score is displayed correctly
    scoreElement.textContent = correctAnswers;
}

// Render questions list with pagination
function renderQuestionsList() {
    questionsList.innerHTML = '';
    
    const startIndex = (currentPage - 1) * questionsPerPage;
    const endIndex = Math.min(startIndex + questionsPerPage, quizData.length);
    
    for (let i = startIndex; i < endIndex; i++) {
        const question = quizData[i];
        const questionElement = document.createElement('div');
        questionElement.className = `question-item${question.id === currentQuestionId ? ' selected' : ''}`;
        questionElement.dataset.id = question.id;
        
        // Add indicator for answered questions
        const status = answeredQuestions.has(question.id) ? '✓ ' : '';
        
        questionElement.textContent = `${status}Q${question.id}: ${question.question.substring(0, 30)}${question.question.length > 30 ? '...' : ''}`;
        
        questionElement.addEventListener('click', () => {
            selectQuestion(question.id);
        });
        
        questionsList.appendChild(questionElement);
    }
    
    // Update pagination
    updatePaginationControls();
}

// Update pagination buttons and info
function updatePaginationControls() {
    const totalPages = Math.ceil(quizData.length / questionsPerPage);
    
    prevPageBtn.disabled = currentPage <= 1;
    nextPageBtn.disabled = currentPage >= totalPages;
    
    pageInfoElement.textContent = `Page ${currentPage} of ${totalPages}`;
}

// Handle pagination
function handlePagination() {
    prevPageBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderQuestionsList();
        }
    });
    
    nextPageBtn.addEventListener('click', () => {
        const totalPages = Math.ceil(quizData.length / questionsPerPage);
        if (currentPage < totalPages) {
            currentPage++;
            renderQuestionsList();
        }
    });
}

// Select a question and display it
function selectQuestion(questionId) {
    console.log('Selecting question with ID:', questionId);
    
    // Ensure questionId is a number
    questionId = parseInt(questionId, 10);
    currentQuestionId = questionId;
    
    // Update URL with current question ID
    updateURLWithQuestionId(questionId);
    
    // Find the page where this question would be
    const questionIndex = quizData.findIndex(q => q.id === questionId);
    if (questionIndex === -1) {
        console.error('Question not found with ID:', questionId);
        return;
    }
    
    // Make sure we're on the correct page for this question
    const targetPage = Math.ceil((questionIndex + 1) / questionsPerPage);
    if (currentPage !== targetPage) {
        currentPage = targetPage;
        renderQuestionsList();
    }
    
    // Update selected class in the list
    document.querySelectorAll('.question-item.selected').forEach(item => {
        item.classList.remove('selected');
    });
    
    const selectedItem = document.querySelector(`.question-item[data-id="${questionId}"]`);
    if (selectedItem) {
        selectedItem.classList.add('selected');
        
        // Only scroll the item into view when directly clicking on questions list
        // but not when answering or navigating with buttons
        if (!window.preventScrollOnSelect) {
            selectedItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }
    
    // Get the selected question
    const question = quizData[questionIndex];
    
    console.log('Found question:', question.question);
    
    // Update navigation button states
    updateNavigationState();
    
    // Display the question
    questionDisplay.innerHTML = `
        <h3>Question ${question.id}</h3>
        <p>${question.question.replaceAll("\n", "<br>")}</p>
    `;
    
    // Display answer options
    displayAnswers(question);
    
    // Save session after selecting a new question
    saveSessionData();
}

// Display answer options for a question
function displayAnswers(question) {
    answersContainer.innerHTML = '';
    
    // Ensure question.id is treated as a number
    const questionId = parseInt(question.id, 10);
    const isAnswered = answeredQuestions.has(questionId);
    
    question.answers.forEach(answer => {
        const answerElement = document.createElement('div');
        answerElement.className = 'answer-option';
        answerElement.textContent = answer;
        
        // If question has been answered, show correct/incorrect styling and disable interaction
        if (isAnswered) {
            if (answer === question.correct) {
                answerElement.classList.add('correct');
            } else {
                // Don't mark all other answers as incorrect, just leave them neutral
                answerElement.style.cursor = 'default';
            }
        } else {
            // Add click event only if question hasn't been answered
            answerElement.addEventListener('click', () => {
                handleAnswerSelection(answer, question);
            });
        }
        
        answersContainer.appendChild(answerElement);
    });
    
    // Handle auto-answer functionality
    if (isAutoAnswerEnabled && !isAnswered) {
        // Visual feedback that auto-answer will trigger
        const autoAnswerContainer = document.querySelector('.auto-answer-container');
        autoAnswerContainer.classList.add('triggering');
        
        // Set timeout to show the correct answer automatically
        setTimeout(() => {
            // Make sure we're still on the same question when the timeout fires
            if (currentQuestionId === question.id && !answeredQuestions.has(questionId)) {
                showCorrectAnswer(question);
                autoAnswerContainer.classList.remove('triggering');
            }
        }, autoAnswerDelay);
    }
}

// Handle answer selection
function handleAnswerSelection(selectedAnswer, question) {
    // Ensure question.id is treated as a number
    const questionId = parseInt(question.id, 10);
    
    // Prevent answering if already answered
    if (answeredQuestions.has(questionId)) {
        return;
    }
    
    // Set flag to prevent automatic scrolling
    window.preventScrollOnSelect = true;
    
    // Mark question as answered
    answeredQuestions.add(questionId);
    
    // Update the question item in the list to show it's been answered
    const questionItem = document.querySelector(`.question-item[data-id="${question.id}"]`);
    if (questionItem && !questionItem.textContent.startsWith('✓')) {
        // Add the checkmark only if it doesn't already have one
        questionItem.textContent = `✓ ${questionItem.textContent}`;
    }
    
    // Check if answer is correct
    const isCorrect = selectedAnswer === question.correct;
    
    // Update score if correct
    if (isCorrect) {
        correctAnswers++;
        scoreElement.textContent = correctAnswers;
    }    // Highlight answers
    const answerOptions = answersContainer.querySelectorAll('.answer-option');
    answerOptions.forEach(option => {
        const clonedOption = option.cloneNode(true);
        
        // Add correct/incorrect classes before replacing
        if (option.textContent === question.correct) {
            clonedOption.classList.add('correct');
        } else if (option.textContent === selectedAnswer && !isCorrect) {
            clonedOption.classList.add('incorrect');
        }
        
        // Replace with the cloned element (removing event listeners)
        option.replaceWith(clonedOption);
    });
    
    // Auto-next functionality
    if (isAutoNextEnabled) {
        console.log('Auto-next is enabled, preparing to move to next question');
        // Visual feedback that auto-next will happen
        const autoNextContainer = document.querySelector('.auto-next-container');
        autoNextContainer.classList.add('triggering');
          setTimeout(() => {
            console.log('Auto-next timeout triggered, current question ID:', currentQuestionId);
            autoNextContainer.classList.remove('triggering');
            goToNextQuestion();
        }, 1000); // Move to next question after 1 second
    }
    
    // Reset the scroll prevention flag
    window.preventScrollOnSelect = false;
    
    // Save session data after answering a question
    saveSessionData();
}

// Navigate to previous question
function goToPreviousQuestion() {
    if (!currentQuestionId) return;
    
    // Find current index in quizData array
    const currentIndex = quizData.findIndex(q => q.id === currentQuestionId);
    console.log('Current index for previous:', currentIndex);
    
    // Return if we're at the first question
    if (currentIndex <= 0) {
        console.log('At the first question, cannot go to previous question');
        return;
    }
    
    // Get the previous question's ID from the array
    const prevId = quizData[currentIndex - 1].id;
    console.log('Moving to previous question with ID:', prevId);
    
    // Set flag to prevent automatic scrolling
    window.preventScrollOnSelect = true;
    selectQuestion(prevId);
    window.preventScrollOnSelect = false;
    
    // Make sure the question is visible in the list
    ensureQuestionIsVisible(prevId);
}

// Navigate to next question
function goToNextQuestion() {
    if (!currentQuestionId) return;
    
    // Find current index in quizData array
    const currentIndex = quizData.findIndex(q => q.id === currentQuestionId);
    console.log('Current index:', currentIndex, 'quizData length:', quizData.length);
    
    // Return if we're at the last question
    if (currentIndex === -1 || currentIndex >= quizData.length - 1) {
        console.log('At the last question or invalid index, cannot go to next question');
        return;
    }
    
    // Get the next question's ID from the array
    const nextId = quizData[currentIndex + 1].id;
    console.log('Moving to next question with ID:', nextId);
    
    // Set flag to prevent automatic scrolling
    window.preventScrollOnSelect = true;
    selectQuestion(nextId);
    window.preventScrollOnSelect = false;
    
    // Make sure the question is visible in the list
    ensureQuestionIsVisible(nextId);
}

// Make sure the selected question is visible in the pagination
function ensureQuestionIsVisible(questionId) {
    // Find the index of the question in the current quizData array
    const questionIndex = quizData.findIndex(q => q.id === questionId);
    
    // Calculate which page this question should be on (1-based index)
    const targetPage = Math.ceil((questionIndex + 1) / questionsPerPage);
    
    // Change page if needed
    if (targetPage !== currentPage) {
        currentPage = targetPage;
        renderQuestionsList();
    }
}

// Handle question navigation
function handleQuestionNavigation() {
    // Previous question button
    prevQuestionBtn.addEventListener('click', goToPreviousQuestion);
    
    // Next question button
    nextQuestionBtn.addEventListener('click', goToNextQuestion);
    
    // Shuffle toggle
    autoNextToggle.addEventListener('change', (e) => {
        isAutoNextEnabled = e.target.checked;
        
        // Visual feedback when auto-next is enabled/disabled
        const container = document.querySelector('.auto-next-container');
        if (isAutoNextEnabled) {
            container.classList.add('active');
            container.title = 'Auto Next is enabled - will proceed to next question 1 second after answering';
        } else {
            container.classList.remove('active');
            container.title = 'Auto Next is disabled';
        }
    });
      // Auto-answer toggle
    autoAnswerToggle.addEventListener('change', (e) => {
        isAutoAnswerEnabled = e.target.checked;
        
        // Visual feedback when auto-answer is enabled/disabled
        const container = document.querySelector('.auto-answer-container');
        if (isAutoAnswerEnabled) {
            container.classList.add('active');
            container.title = 'Auto Answer is enabled - will show correct answer after 2 seconds';
            
            // Immediately show answer for current question if it hasn't been answered yet
            if (currentQuestionId && !answeredQuestions.has(currentQuestionId)) {
                const currentQuestion = quizData.find(q => q.id === currentQuestionId);
                if (currentQuestion) {
                    // Visual feedback that auto-answer will trigger
                    container.classList.add('triggering');
                    
                    setTimeout(() => {
                        // Check again if question is still unanswered when timeout completes
                        if (!answeredQuestions.has(currentQuestionId)) {
                            showCorrectAnswer(currentQuestion);
                        }
                        container.classList.remove('triggering');
                    }, autoAnswerDelay);
                }
            }
        } else {
            container.classList.remove('active');
            container.title = 'Auto Answer is disabled';
        }
    });
    
    // Shuffle toggle
    shuffleToggle.addEventListener('change', (e) => {
        isShuffleEnabled = e.target.checked;
        
        // Visual feedback when shuffle is enabled/disabled
        const container = document.querySelector('.shuffle-container');
        if (isShuffleEnabled) {
            container.classList.add('active');
            container.title = 'Shuffle is enabled - questions are in random order';
            
            // Remember current question before shuffling
            const currentQuestion = quizData.find(q => q.id === currentQuestionId);
            const currentQuestionIndex = currentQuestion ? quizData.indexOf(currentQuestion) : 0;
            
            // Reset score and answered questions when shuffling
            if (answeredQuestions.size > 0) {
                if (confirm('Shuffling will reset your progress. Continue?')) {
                    answeredQuestions = new Set();
                    correctAnswers = 0;
                    scoreElement.textContent = '0';
                } else {
                    // If user cancels, uncheck the toggle and exit
                    shuffleToggle.checked = false;
                    isShuffleEnabled = false;
                    container.classList.remove('active');
                    return;
                }
            }
            
            // Shuffle questions
            shuffleQuestions();
            currentPage = 1; // Reset to first page
            
            // Select first question or maintain relative position
            if (quizData.length > 0) {
                let newIndex = Math.min(currentQuestionIndex, quizData.length - 1);
                selectQuestion(quizData[newIndex].id);
            }
            
            // Update UI
            renderQuestionsList();
        } else {
            container.classList.remove('active');
            container.title = 'Shuffle is disabled - questions are in original order';
            
            // Remember current question position
            const currentQuestion = quizData.find(q => q.id === currentQuestionId);
            const currentQuestionIndex = currentQuestion ? quizData.indexOf(currentQuestion) : 0;
            
            // Reset to original order
            quizData = JSON.parse(JSON.stringify(originalQuizData));
            currentPage = 1; // Reset to first page
            
            // Select question at same relative position
            if (quizData.length > 0) {
                let newIndex = Math.min(currentQuestionIndex, quizData.length - 1);
                selectQuestion(quizData[newIndex].id);
            }
            
            // Update UI
            renderQuestionsList();
        }
    });
}

// Function to show the correct answer
function showCorrectAnswer(question) {
    console.log('Auto showing correct answer for question:', question.id);
    const questionId = parseInt(question.id, 10);
    
    // Mark question as answered
    answeredQuestions.add(questionId);
    
    // Set flag to prevent automatic scrolling
    window.preventScrollOnSelect = true;
    
    // Update the question item in the list to show it's been answered
    const questionItem = document.querySelector(`.question-item[data-id="${question.id}"]`);
    if (questionItem && !questionItem.textContent.startsWith('✓')) {
        questionItem.textContent = `✓ ${questionItem.textContent}`;
    }
    
    // Update score - for auto answer always count as correct
    correctAnswers++;
    scoreElement.textContent = correctAnswers;
    
    // Highlight the correct answer
    const answerOptions = answersContainer.querySelectorAll('.answer-option');
    answerOptions.forEach(option => {
        const clonedOption = option.cloneNode(true);
        
        if (option.textContent === question.correct) {
            clonedOption.classList.add('correct');
        } else {
            // Make all other options non-interactive
            clonedOption.style.cursor = 'default';
        }
        
        option.replaceWith(clonedOption);
    });
    
    // Reset scroll prevention flag
    window.preventScrollOnSelect = false;
      // If auto-next is also enabled, move to next question
    if (isAutoNextEnabled) {
        setTimeout(() => {
            goToNextQuestion();
        }, 1000);
    }
    
    // Save session data after showing correct answer
    saveSessionData();
}

// Update navigation button states
function updateNavigationState() {
    if (!currentQuestionId) return;
    
    // Find current index in quizData array
    const currentIndex = quizData.findIndex(q => q.id === currentQuestionId);
    console.log('Updating navigation state, current index:', currentIndex);
    
    prevQuestionBtn.disabled = currentIndex <= 0;
    nextQuestionBtn.disabled = currentIndex >= quizData.length - 1;
}

// Session persistence functions
function saveSessionData() {
    const sessionData = {
        answeredQuestions: Array.from(answeredQuestions),
        correctAnswers: correctAnswers,
        currentQuestionId: currentQuestionId,
        currentPage: currentPage,
        isAutoNextEnabled: isAutoNextEnabled,
        isAutoAnswerEnabled: isAutoAnswerEnabled,
        isShuffleEnabled: isShuffleEnabled,
        quizData: isShuffleEnabled ? quizData : null // Only save shuffled data if shuffle is enabled
    };
    
    localStorage.setItem('quizSessionData', JSON.stringify(sessionData));
    console.log('Session data saved');
}

function loadSessionData() {
    const sessionDataString = localStorage.getItem('quizSessionData');
    if (!sessionDataString) {
        console.log('No saved session found');
        return false;
    }
    
    try {
        const sessionData = JSON.parse(sessionDataString);
        
        // Restore answered questions
        answeredQuestions = new Set(sessionData.answeredQuestions);
        
        // Restore score
        correctAnswers = sessionData.correctAnswers;
        scoreElement.textContent = correctAnswers;
        
        // Restore toggle states
        isAutoNextEnabled = sessionData.isAutoNextEnabled;
        autoNextToggle.checked = isAutoNextEnabled;
        if (isAutoNextEnabled) {
            document.querySelector('.auto-next-container').classList.add('active');
        }
        
        isAutoAnswerEnabled = sessionData.isAutoAnswerEnabled;
        autoAnswerToggle.checked = isAutoAnswerEnabled;
        if (isAutoAnswerEnabled) {
            document.querySelector('.auto-answer-container').classList.add('active');
        }
        
        // Restore shuffle state and shuffled data if available
        isShuffleEnabled = sessionData.isShuffleEnabled;
        shuffleToggle.checked = isShuffleEnabled;
        if (isShuffleEnabled) {
            document.querySelector('.shuffle-container').classList.add('active');
            
            // If we have saved shuffled data, use it
            if (sessionData.quizData) {
                quizData = sessionData.quizData;
            } else {
                // Otherwise shuffle again
                shuffleQuestions();
            }
        }
        
        // Restore page and question selection
        currentPage = sessionData.currentPage;
        
        console.log('Session data loaded successfully');
        return true;
    } catch (error) {
        console.error('Error loading session data:', error);
        return false;
    }
}

// Reset all progress
function resetProgress() {
    // Confirm with the user before resetting
    if (!confirm('Are you sure you want to reset all progress? This cannot be undone.')) {
        return;
    }
    
    // Reset variables
    answeredQuestions = new Set();
    correctAnswers = 0;
    
    // Reset score display
    scoreElement.textContent = '0';
    
    // Reset shuffle if enabled
    if (isShuffleEnabled) {
        // Keep shuffle enabled but reset the order
        shuffleQuestions();
    } else {
        // Make sure we're using the original data
        quizData = JSON.parse(JSON.stringify(originalQuizData));
    }
    
    // Reset to page 1
    currentPage = 1;
    
    // Select the first question
    if (quizData.length > 0) {
        selectQuestion(quizData[0].id);
    }
    
    // Update UI
    renderQuestionsList();
    
    // Clear localStorage
    localStorage.removeItem('quizSessionData');
    
    // Show confirmation message
    alert('Progress has been reset successfully!');
}

// Initialize the app
function initApp() {
    loadQuizData();
    handlePagination();
    handleQuestionNavigation();
    
    // Set up Reset Progress button
    resetProgressBtn.addEventListener('click', resetProgress);
    
    // Check if there's a question ID in the URL
    const urlQuestionId = getQueryParam('id');
    
    // Try to load saved session
    const sessionLoaded = loadSessionData();
    
    if (urlQuestionId) {
        // URL parameter takes precedence
        const questionId = parseInt(urlQuestionId, 10);
        const questionExists = quizData.some(q => q.id === questionId);
        
        if (questionExists) {
            // If question ID from URL is valid, use it
            selectQuestion(questionId);
        } else {
            console.warn(`Question with ID ${questionId} not found, using default`);
            // Fall back to the saved question or the first question
            if (sessionLoaded && currentQuestionId) {
                selectQuestion(currentQuestionId);
            } else if (quizData.length > 0) {
                selectQuestion(quizData[0].id);
            }
        }
    } else if (sessionLoaded) {
        // No URL parameter, use saved session
        // Render the list with the restored page
        renderQuestionsList();
        
        // Restore current question if it exists
        if (currentQuestionId) {
            selectQuestion(currentQuestionId);
        } else if (quizData.length > 0) {
            selectQuestion(quizData[0].id);
        }
    } else {
        // No URL parameter and no saved session
        // Default: load the first question automatically
        if (quizData.length > 0) {
            selectQuestion(quizData[0].id);
        }
    }
    
    // Set up auto-save
    // Save every 5 seconds if there are changes
    setInterval(saveSessionData, 5000);
    
    // Save when leaving the page
    window.addEventListener('beforeunload', saveSessionData);
}

// Start the app when DOM is ready
document.addEventListener('DOMContentLoaded', initApp);

// Handle URL changes for browser navigation (back/forward buttons)
window.addEventListener('popstate', function(event) {
    const urlQuestionId = getQueryParam('id');
    if (urlQuestionId) {
        const questionId = parseInt(urlQuestionId, 10);
        const questionExists = quizData.some(q => q.id === questionId);
        
        if (questionExists) {
            selectQuestion(questionId);
        }
    }
});
