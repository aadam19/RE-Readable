const express = require('express');
const router = express.Router();
const Post = require('../models/Post')

// Routes
function truncateString(str, num) {
    if (str.length <= num) {
        return str;
    }
    return str.slice(0, num) + '...';
}

/* GET HOME */
router.get('', async (req, res) => {
    try {
        const locals = {
            title: "RE | Readable",
            description: "eCommerce for used books"
        }

        let perPage = 24;
        let page = req.query.page || 1;

        const data = await Post.aggregate([ { $sort: { createdAt: -1 } } ])
            .skip(perPage * page - perPage)
            .limit(perPage)
            .exec();
        
        const count = await Post.countDocuments();
        const nextPage = parseInt(page) + 1;
        const previousPage = parseInt(page) - 1;
        const hasNextPage = nextPage <= Math.ceil(count / perPage);
        const hasPreviousPage = previousPage > 0;
        const lastPage = 

        res.render('index', { 
            locals, 
            data, 
            truncateString,
            count,
            perPage,
            current: page,
            nextPage: hasNextPage ? nextPage : null,
            previousPage: hasPreviousPage? previousPage : null
        })
    } catch (error) {
        console.log(error)
    }
    
});

/* GET _ID */
router.get('/books/:id', async (req, res)=> {
    try {
        const locals = {
            title: "RE | Readable",
            description: "eCommerce for used books"
        }
        let slug = req.params.id;
        const data = await Post.findById({ _id: slug });

        res.render('books', {
            locals, 
            data
        });

    } catch (error) {
        console.log(error)
    }
})


/* POST SEARCH */
router.post('/search', async (req, res)=>{
    try {
        const locals = {
            title: "Search",
            description: "eCommerce for used books"
        }
        let searchTerm = req.body.searchTerm;
        const searchNoSpecial = searchTerm.replace(/[^a-zA-Z0-9]/g, "");


        const data = await Post.find({ 
            $or: [
                { title: { $regex: new RegExp(searchNoSpecial, 'i') } },
                { body: { $regex: new RegExp(searchNoSpecial, 'i') } },
            ]
         });

        res.render("search", {
            data,
            locals,
            searchTerm,
            truncateString
        });
    } catch (error) {
        console.log(error)
    }
})


module.exports = router;